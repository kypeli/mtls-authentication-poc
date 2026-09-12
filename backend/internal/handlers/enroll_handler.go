package handlers

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/kypeli/mtls-poc/backend/internal/attestation"
	"github.com/kypeli/mtls-poc/backend/internal/ca"
	"github.com/kypeli/mtls-poc/backend/internal/storage"
)

const (
	// maxEnrollBodyBytes bounds the enrollment JSON body to prevent unbounded
	// memory use from oversized attestation chains.
	maxEnrollBodyBytes = 256 << 10
)

// deviceLabelPattern constrains the client-supplied label: alphanumeric with
// dots, underscores, and hyphens; it is a display label only and never becomes
// an identity. It is safe for inclusion in certificate fields and logs.
var deviceLabelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// EnrollRequest represents the incoming enrollment JSON payload.
// The attestation challenge is extracted from the chain, never from this body.
type EnrollRequest struct {
	DeviceID         string   `json:"device_id,omitempty"`
	CSR              string   `json:"csr"`
	AttestationChain []string `json:"attestation_chain"`
}

// EnrollResponse represents the enrollment JSON response.
type EnrollResponse struct {
	ClientCertificate string   `json:"client_certificate"`
	CaCertificate     string   `json:"ca_certificate"`
	CertificateChain  []string `json:"certificate_chain"`
	// DeviceIdentity is the server-derived identity (attested public key hash).
	DeviceIdentity string `json:"device_identity,omitempty"`
	// DeviceLabel echoes the client-supplied label.
	DeviceLabel string `json:"device_label,omitempty"`
}

// EnrollHandler handles device key attestation verification and certificate issuance.
type EnrollHandler struct {
	ca            *ca.CA
	caPEM         string
	verifier      *attestation.Verifier
	store         storage.ChallengeStore
	deviceRepo    storage.DeviceRepo
	clientCertTTL time.Duration
}

// NewEnrollHandler creates an EnrollHandler.
func NewEnrollHandler(
	caInstance *ca.CA,
	caPEM string,
	verifier *attestation.Verifier,
	store storage.ChallengeStore,
	deviceRepo storage.DeviceRepo,
	clientCertTTL time.Duration,
) *EnrollHandler {
	return &EnrollHandler{
		ca:            caInstance,
		caPEM:         caPEM,
		verifier:      verifier,
		store:         store,
		deviceRepo:    deviceRepo,
		clientCertTTL: clientCertTTL,
	}
}

func (h *EnrollHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Bound the request body so a large attestation chain cannot exhaust memory.
	r.Body = http.MaxBytesReader(w, r.Body, maxEnrollBodyBytes)

	var req EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[ENROLL] ❌ Invalid JSON body from %s: %v", r.RemoteAddr, err)
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	label := req.DeviceID
	if label != "" && !deviceLabelPattern.MatchString(label) {
		log.Printf("[ENROLL] ❌ Invalid device_id label %q from %s", label, r.RemoteAddr)
		http.Error(w, "invalid device_id label", http.StatusBadRequest)
		return
	}

	log.Printf("[ENROLL] 📥 Received enrollment request (label=%q) from %s", label, r.RemoteAddr)

	if req.CSR == "" {
		http.Error(w, "csr is required", http.StatusBadRequest)
		return
	}

	csrDER, err := base64.StdEncoding.DecodeString(req.CSR)
	if err != nil {
		log.Printf("[ENROLL] ❌ Failed to decode base64 CSR (label=%q) from %s: %v", label, r.RemoteAddr, err)
		http.Error(w, "failed to decode base64 CSR", http.StatusBadRequest)
		return
	}

	parsedCSR, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		log.Printf("[ENROLL] ❌ Invalid CSR DER (label=%q) from %s: %v", label, r.RemoteAddr, err)
		http.Error(w, "invalid CSR", http.StatusBadRequest)
		return
	}

	policy := h.verifier.Policy()

	if !policy.AllowEmptyAttestation && len(req.AttestationChain) < 2 {
		log.Printf("[ENROLL] ❌ Attestation chain too short (%d certs) for label=%q", len(req.AttestationChain), label)
		http.Error(w, "attestation_chain must contain at least leaf and intermediate certificates", http.StatusBadRequest)
		return
	}

	chainDER := make([][]byte, 0, len(req.AttestationChain))
	for i, certB64 := range req.AttestationChain {
		der, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			log.Printf("[ENROLL] ❌ Failed to decode cert at index %d (label=%q): %v", i, label, err)
			http.Error(w, "failed to decode certificate in attestation_chain", http.StatusBadRequest)
			return
		}
		chainDER = append(chainDER, der)
	}

	// The challenge nonce is bound to the attested key inside the attestation
	// extension; it must be extracted from the chain, never from the request.
	var challengeBytes []byte
	if len(chainDER) > 0 {
		challengeBytes, err = attestation.ExtractChallenge(chainDER)
		if err != nil {
			log.Printf("[ENROLL] ❌ Could not extract attestation challenge (label=%q): %v", label, err)
			if !policy.AllowEmptyAttestation {
				http.Error(w, "attestation challenge could not be located", http.StatusBadRequest)
				return
			}
			challengeBytes = nil
		}
	}

	if len(challengeBytes) > 0 {
		challengeB64 := base64.StdEncoding.EncodeToString(challengeBytes)
		if !h.store.VerifyAndConsumeChallenge(challengeB64) {
			log.Printf("[ENROLL] ❌ Invalid or expired attestation challenge (label=%q)", label)
			http.Error(w, "invalid or expired attestation challenge", http.StatusBadRequest)
			return
		}
	} else if !policy.AllowEmptyAttestation {
		http.Error(w, "attestation challenge is required", http.StatusBadRequest)
		return
	}

	// Perform Android Key Attestation verification
	record, err := h.verifier.VerifyAttestation(chainDER, challengeBytes, parsedCSR.PublicKey)
	if err != nil {
		log.Printf("[ENROLL] ❌ Attestation verification failed (label=%q): %v", label, err)
		http.Error(w, "attestation verification failed", http.StatusForbidden)
		return
	}

	// Identity is derived server-side from the attested public key hash; the
	// client-chosen device_id is only a label.
	identity, err := attestation.PublicKeyFingerprint(parsedCSR.PublicKey)
	if err != nil {
		log.Printf("[ENROLL] ❌ Failed to derive identity from public key (label=%q): %v", label, err)
		http.Error(w, "failed to derive device identity", http.StatusInternalServerError)
		return
	}

	log.Printf("[ENROLL] 🛡️ Attestation verified (label=%q): identity=%s, HardwareSecurityLevel=%s",
		label, shortIdentity(identity), record.AttestationSecurityLevel)

	// Refuse enrollment when this identity (the attested key) has been revoked;
	// re-enrolling with the same key would otherwise bypass revocation.
	if existing, getErr := h.deviceRepo.GetDevice(identity); getErr == nil && existing.IsRevoked {
		log.Printf("[ENROLL] ❌ Identity %s is revoked; re-enrollment refused", shortIdentity(identity))
		http.Error(w, "device identity is revoked", http.StatusForbidden)
		return
	}

	// Sign CSR via in-process CA. The certificate CN carries the server-derived
	// identity, not the client label.
	clientCert, clientPEM, err := h.ca.SignCSR(csrDER, identity, h.clientCertTTL)
	if err != nil {
		log.Printf("[ENROLL] ❌ Failed to sign CSR (label=%q): %v", label, err)
		http.Error(w, "failed to sign CSR", http.StatusInternalServerError)
		return
	}

	// Persist the device record before responding. If the write fails, the
	// freshly issued certificate is revoked so no valid but untracked
	// certificate remains in circulation.
	devRecord := storage.DeviceRecord{
		Identity:              identity,
		Label:                 label,
		CertSerial:            clientCert.SerialNumber.String(),
		EnrolledAt:            time.Now(),
		IsRevoked:             false,
		HardwareSecurityLevel: record.AttestationSecurityLevel.String(),
	}
	if err := h.deviceRepo.RegisterDevice(devRecord); err != nil {
		_ = h.deviceRepo.RevokeSerial(clientCert.SerialNumber.String())
		log.Printf("[ENROLL] ❌ Failed to persist device record for %s: %v (serial %s revoked)", shortIdentity(identity), err, clientCert.SerialNumber.String())
		http.Error(w, "failed to persist device record", http.StatusInternalServerError)
		return
	}

	log.Printf("[ENROLL] 📜 Issued client certificate for identity=%s (label=%q): Serial=%s, TTL=%v",
		shortIdentity(identity), label, clientCert.SerialNumber.String(), h.clientCertTTL)

	clientPEMStr := string(clientPEM)
	resp := EnrollResponse{
		ClientCertificate: clientPEMStr,
		CaCertificate:     h.caPEM,
		CertificateChain:  []string{clientPEMStr, h.caPEM},
		DeviceIdentity:    identity,
		DeviceLabel:       label,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// shortIdentity truncates a hex identity for compact log output.
func shortIdentity(identity string) string {
	if len(identity) <= 16 {
		return identity
	}
	return identity[:16] + "..."
}
