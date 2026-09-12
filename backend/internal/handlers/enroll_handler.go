package handlers

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/kypeli/mtls-poc/backend/internal/attestation"
	"github.com/kypeli/mtls-poc/backend/internal/ca"
	"github.com/kypeli/mtls-poc/backend/internal/storage"
)

// EnrollRequest represents the incoming enrollment JSON payload.
// Supports both 'csr' and 'csr_der', and optional explicit 'challenge'.
type EnrollRequest struct {
	DeviceID         string   `json:"device_id"`
	Challenge        string   `json:"challenge,omitempty"`
	CSR              string   `json:"csr,omitempty"`
	CSRDer           string   `json:"csr_der,omitempty"`
	AttestationChain []string `json:"attestation_chain"`
}

// EnrollResponse represents the enrollment JSON response.
type EnrollResponse struct {
	ClientCertificate string   `json:"client_certificate"`
	CaCertificate     string   `json:"ca_certificate"`
	CertificateChain  []string `json:"certificate_chain"`
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

	var req EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[ENROLL] ❌ Invalid JSON body from %s: %v", r.RemoteAddr, err)
		http.Error(w, fmt.Sprintf("Invalid JSON body: %v", err), http.StatusBadRequest)
		return
	}

	log.Printf("[ENROLL] 📥 Received enrollment request for device_id=%q from %s", req.DeviceID, r.RemoteAddr)

	if req.DeviceID == "" {
		http.Error(w, "device_id is required", http.StatusBadRequest)
		return
	}

	csrBase64 := req.CSR
	if csrBase64 == "" {
		csrBase64 = req.CSRDer
	}
	if csrBase64 == "" {
		http.Error(w, "csr or csr_der is required", http.StatusBadRequest)
		return
	}

	csrDER, err := base64.StdEncoding.DecodeString(csrBase64)
	if err != nil {
		log.Printf("[ENROLL] ❌ Failed to decode base64 CSR for device_id=%q from %s: %v", req.DeviceID, r.RemoteAddr, err)
		http.Error(w, "failed to decode base64 CSR", http.StatusBadRequest)
		return
	}

	parsedCSR, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		log.Printf("[ENROLL] ❌ Invalid CSR DER for device_id=%q from %s: %v", req.DeviceID, r.RemoteAddr, err)
		http.Error(w, fmt.Sprintf("invalid CSR DER: %v", err), http.StatusBadRequest)
		return
	}

	policy := h.verifier.Policy()

	if !policy.AllowEmptyAttestation && len(req.AttestationChain) < 2 {
		log.Printf("[ENROLL] ❌ Attestation chain too short (%d certs) for device_id=%q", len(req.AttestationChain), req.DeviceID)
		http.Error(w, "attestation_chain must contain at least leaf and intermediate certificates", http.StatusBadRequest)
		return
	}

	chainDER := make([][]byte, 0, len(req.AttestationChain))
	for i, certB64 := range req.AttestationChain {
		der, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			log.Printf("[ENROLL] ❌ Failed to decode cert at index %d for device_id=%q: %v", i, req.DeviceID, err)
			http.Error(w, fmt.Sprintf("failed to decode certificate at index %d: %v", i, err), http.StatusBadRequest)
			return
		}
		chainDER = append(chainDER, der)
	}

	// Determine challenge: from request field or extracted from attestation extension
	challengeB64 := req.Challenge
	var challengeBytes []byte
	if challengeB64 != "" {
		challengeBytes, err = base64.StdEncoding.DecodeString(challengeB64)
		if err != nil {
			log.Printf("[ENROLL] ❌ Invalid base64 challenge for device_id=%q: %v", req.DeviceID, err)
			http.Error(w, "invalid base64 challenge in request", http.StatusBadRequest)
			return
		}
	} else if len(chainDER) > 0 {
		// Extract from leaf certificate
		leafCert, err := x509.ParseCertificate(chainDER[0])
		if err == nil {
			for _, ext := range leafCert.Extensions {
				if ext.Id.String() == attestation.AndroidKeyAttestationOID {
					var kd attestation.KeyDescription
					if _, err := asn1.Unmarshal(ext.Value, &kd); err == nil {
						challengeBytes = kd.AttestationChallenge
						challengeB64 = base64.StdEncoding.EncodeToString(challengeBytes)
					}
					break
				}
			}
		}
	}

	if len(challengeBytes) == 0 && !policy.AllowEmptyAttestation {
		log.Printf("[ENROLL] ❌ Attestation challenge could not be located for device_id=%q", req.DeviceID)
		http.Error(w, "attestation challenge could not be located", http.StatusBadRequest)
		return
	}

	// Verify and consume challenge from challenge store (single use) if a challenge was provided/located
	if challengeB64 != "" {
		if !h.store.VerifyAndConsumeChallenge(challengeB64) {
			log.Printf("[ENROLL] ❌ Invalid or expired attestation challenge for device_id=%q", req.DeviceID)
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
		log.Printf("[ENROLL] ❌ Attestation verification failed for device_id=%q: %v", req.DeviceID, err)
		http.Error(w, fmt.Sprintf("attestation verification failed: %v", err), http.StatusForbidden)
		return
	}

	log.Printf("[ENROLL] 🛡️ Attestation verified for device_id=%q: HardwareSecurityLevel=%s",
		req.DeviceID, record.AttestationSecurityLevel)

	// Sign CSR via in-process CA
	clientCert, clientPEM, err := h.ca.SignCSR(csrDER, req.DeviceID, h.clientCertTTL)
	if err != nil {
		log.Printf("[ENROLL] ❌ Failed to sign CSR for device_id=%q: %v", req.DeviceID, err)
		http.Error(w, fmt.Sprintf("failed to sign CSR: %v", err), http.StatusInternalServerError)
		return
	}

	// Calculate public key fingerprint
	pubKeyPKIX, _ := x509.MarshalPKIXPublicKey(parsedCSR.PublicKey)
	fingerprint := sha256.Sum256(pubKeyPKIX)

	// Persist device record
	devRecord := storage.DeviceRecord{
		DeviceID:              req.DeviceID,
		PublicKeyFingerprint:  hex.EncodeToString(fingerprint[:]),
		CertSerial:            clientCert.SerialNumber.String(),
		EnrolledAt:            time.Now(),
		IsRevoked:             false,
		HardwareSecurityLevel: record.AttestationSecurityLevel.String(),
	}
	_ = h.deviceRepo.RegisterDevice(devRecord)

	log.Printf("[ENROLL] 📜 Issued client certificate for device_id=%q: Serial=%s, TTL=%v",
		req.DeviceID, clientCert.SerialNumber.String(), h.clientCertTTL)

	clientPEMStr := string(clientPEM)
	resp := EnrollResponse{
		ClientCertificate: clientPEMStr,
		CaCertificate:     h.caPEM,
		CertificateChain:  []string{clientPEMStr, h.caPEM},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}
