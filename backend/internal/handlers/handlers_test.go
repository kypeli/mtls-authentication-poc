package handlers

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kypeli/mtls-poc/backend/internal/attestation"
	"github.com/kypeli/mtls-poc/backend/internal/ca"
	"github.com/kypeli/mtls-poc/backend/internal/middleware"
	"github.com/kypeli/mtls-poc/backend/internal/storage"
)

func TestChallengeHandler(t *testing.T) {
	store := storage.NewMemoryChallengeStore()
	handler := NewChallengeHandler(store, 60*time.Second)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/enroll/challenge", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var resp ChallengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if resp.Challenge == "" {
		t.Fatal("empty challenge in response")
	}
	if resp.ExpiresIn != 60 {
		t.Errorf("expected 60s expires_in, got %d", resp.ExpiresIn)
	}
}

// buildMockAttestationChain builds a synthetic attestation chain (leaf + root)
// plus the device key/CSR bound to it via the attestation extension. When
// rootKey or deviceKey are non-nil they are reused so multiple chains can share
// a trust anchor or a device key.
func buildMockAttestationChain(t *testing.T, store storage.ChallengeStore, rootKey, deviceKey *ecdsa.PrivateKey) (
	devKey *ecdsa.PrivateKey, csrDER []byte, chainDER [][]byte, root *ecdsa.PrivateKey,
) {
	t.Helper()

	challengeB64, _, err := store.GenerateAndStoreChallenge(60 * time.Second)
	if err != nil {
		t.Fatalf("failed to generate challenge: %v", err)
	}
	challengeBytes, _ := base64.StdEncoding.DecodeString(challengeB64)

	// Build mock attestation root
	if rootKey == nil {
		rootKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	attestRootKey := rootKey
	attestRootTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Mock Attest Root"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	attestRootDER, _ := x509.CreateCertificate(rand.Reader, &attestRootTemplate, &attestRootTemplate, &attestRootKey.PublicKey, attestRootKey)
	attestRootCert, _ := x509.ParseCertificate(attestRootDER)

	// Device key & CSR
	if deviceKey == nil {
		deviceKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	devKey = deviceKey
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "dev-mock-001"},
	}
	csrDER, _ = x509.CreateCertificateRequest(rand.Reader, &csrTemplate, devKey)

	// Leaf attestation extension
	rot := attestation.RootOfTrust{
		VerifiedBootKey:   []byte("boot-key"),
		DeviceLocked:      true,
		VerifiedBootState: 0,
	}
	rotBytes, _ := asn1.Marshal(rot)
	rotTagged, _ := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        attestation.TagRootOfTrust,
		IsCompound: true,
		Bytes:      rotBytes,
	})
	teeSeq, _ := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      rotTagged,
	})
	var teeRaw asn1.RawValue
	_, _ = asn1.Unmarshal(teeSeq, &teeRaw)

	kd := attestation.KeyDescription{
		AttestationVersion:       3,
		AttestationSecurityLevel: asn1.Enumerated(attestation.SecurityLevelStrongBox),
		KeymasterVersion:         4,
		KeymasterSecurityLevel:   asn1.Enumerated(attestation.SecurityLevelStrongBox),
		AttestationChallenge:     challengeBytes,
		TeeEnforced:              teeRaw,
	}
	kdBytes, _ := asn1.Marshal(kd)

	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Device Key"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17},
				Value: kdBytes,
			},
		},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, &leafTemplate, attestRootCert, &devKey.PublicKey, attestRootKey)

	return devKey, csrDER, [][]byte{leafDER, attestRootDER}, rootKey
}

func newTestEnrollHandler(t *testing.T, deviceRepo storage.DeviceRepo, store storage.ChallengeStore, chainDER [][]byte) *EnrollHandler {
	t.Helper()

	caInstance, caPEM, _, err := ca.GenerateCA("Test CA Root", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	rootCert, err := x509.ParseCertificate(chainDER[1])
	if err != nil {
		t.Fatalf("failed to parse mock attestation root: %v", err)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)
	verifier := attestation.MustNewVerifier(rootPool, attestation.DefaultStrictPolicy())

	return NewEnrollHandler(caInstance, string(caPEM), verifier, store, deviceRepo, 7*24*time.Hour)
}

func TestEnrollHandlerAndMtlsFlow(t *testing.T) {
	store := storage.NewMemoryChallengeStore()
	deviceRepo := storage.NewMemoryDeviceRepo()

	// Rebuild the chain so the fresh challenge generated inside the handler is used
	devKey, csrDER, chainDER, _ := buildMockAttestationChain(t, store, nil, nil)
	enrollHandler := newTestEnrollHandler(t, deviceRepo, store, chainDER)

	chainB64 := make([]string, len(chainDER))
	for i, der := range chainDER {
		chainB64[i] = base64.StdEncoding.EncodeToString(der)
	}

	enrollReqBody := EnrollRequest{
		DeviceID:         "dev-mock-001",
		CSR:              base64.StdEncoding.EncodeToString(csrDER),
		AttestationChain: chainB64,
	}
	reqBytes, _ := json.Marshal(enrollReqBody)

	httpReq := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(reqBytes))
	rec := httptest.NewRecorder()

	enrollHandler.ServeHTTP(rec, httpReq)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", rec.Code, rec.Body.String())
	}

	var enrollResp EnrollResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &enrollResp); err != nil {
		t.Fatalf("failed to parse enroll response: %v", err)
	}

	if enrollResp.ClientCertificate == "" {
		t.Fatal("expected client certificate in response")
	}

	// The identity must be derived server-side from the attested public key
	expectedIdentity, err := attestation.PublicKeyFingerprint(&devKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to derive expected identity: %v", err)
	}
	if enrollResp.DeviceIdentity != expectedIdentity {
		t.Fatalf("expected server-derived identity %s, got %s", expectedIdentity, enrollResp.DeviceIdentity)
	}
	if enrollResp.DeviceLabel != "dev-mock-001" {
		t.Fatalf("expected label echo, got %q", enrollResp.DeviceLabel)
	}

	// Device must be registered under the derived identity, not the label
	if !deviceRepo.IsDeviceActive(expectedIdentity) {
		t.Fatal("device should be registered and active under derived identity")
	}

	// Parse the issued client certificate for the mTLS auth test
	block, _ := pem.Decode([]byte(enrollResp.ClientCertificate))
	if block == nil {
		t.Fatal("failed to decode client certificate PEM")
	}
	clientCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse issued client certificate: %v", err)
	}
	if clientCert.Subject.CommonName != expectedIdentity {
		t.Fatalf("expected certificate CN to carry derived identity, got %q", clientCert.Subject.CommonName)
	}

	// Test mTLS ping handler with authenticated context
	pingHandler := NewProtectedPingHandler()
	protectedPipeline := middleware.MtlsAuthMiddleware(deviceRepo)(pingHandler)

	// 1. Unauthenticated request (no TLS certs) -> 401
	unauthReq := httptest.NewRequest(http.MethodGet, "/api/v1/protected/ping", nil)
	unauthRec := httptest.NewRecorder()
	protectedPipeline.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized without certs, got %d", unauthRec.Code)
	}

	// 2. Authenticated request with the issued peer certificate -> 200 OK
	authReq := httptest.NewRequest(http.MethodGet, "/api/v1/protected/ping", nil)
	authReq.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert},
	}
	authRec := httptest.NewRecorder()
	protectedPipeline.ServeHTTP(authRec, authReq)

	if authRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with valid peer cert, got %d: %s", authRec.Code, authRec.Body.String())
	}

	var pingResp ProtectedResponse
	if err := json.Unmarshal(authRec.Body.Bytes(), &pingResp); err != nil {
		t.Fatalf("failed to decode ping response: %v", err)
	}
	if pingResp.ClientIdentity != expectedIdentity || pingResp.Status != "ok" {
		t.Fatalf("unexpected ping response: %+v", pingResp)
	}

	// 3. Revoke device and test -> 403 Forbidden
	_ = deviceRepo.RevokeDevice(expectedIdentity)
	revokedRec := httptest.NewRecorder()
	protectedPipeline.ServeHTTP(revokedRec, authReq)
	if revokedRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for revoked device, got %d", revokedRec.Code)
	}

	// 4. Re-enrollment with the revoked identity (same key, fresh challenge) must be refused
	_, _, reChainDER, _ := buildMockAttestationChain(t, store, nil, devKey)
	reChainB64 := make([]string, len(reChainDER))
	for i, der := range reChainDER {
		reChainB64[i] = base64.StdEncoding.EncodeToString(der)
	}
	reEnrollBody := EnrollRequest{
		DeviceID:         "dev-mock-001",
		CSR:              base64.StdEncoding.EncodeToString(csrDER),
		AttestationChain: reChainB64,
	}
	reEnrollBytes, _ := json.Marshal(reEnrollBody)
	reEnrollReq := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(reEnrollBytes))
	reEnrollRec := httptest.NewRecorder()
	enrollHandler.ServeHTTP(reEnrollRec, reEnrollReq)
	if reEnrollRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when re-enrolling a revoked identity, got %d: %s", reEnrollRec.Code, reEnrollRec.Body.String())
	}
}

func TestEnrollHandlerRejectsForeignIdentity(t *testing.T) {
	store := storage.NewMemoryChallengeStore()
	deviceRepo := storage.NewMemoryDeviceRepo()

	// Enroll device A
	_, csrDERA, chainDERA, sharedRoot := buildMockAttestationChain(t, store, nil, nil)
	enrollHandler := newTestEnrollHandler(t, deviceRepo, store, chainDERA)
	chainB64A := make([]string, len(chainDERA))
	for i, der := range chainDERA {
		chainB64A[i] = base64.StdEncoding.EncodeToString(der)
	}
	reqA, _ := json.Marshal(EnrollRequest{
		DeviceID:         "victim-label",
		CSR:              base64.StdEncoding.EncodeToString(csrDERA),
		AttestationChain: chainB64A,
	})
	recA := httptest.NewRecorder()
	enrollHandler.ServeHTTP(recA, httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(reqA)))
	if recA.Code != http.StatusCreated {
		t.Fatalf("expected 201 for first enrollment, got %d: %s", recA.Code, recA.Body.String())
	}

	// Device B (genuine but different key) attempts to enroll under the same
	// label. It gets its own derived identity and cannot impersonate device A.
	_, csrDERB, chainDERB, _ := buildMockAttestationChain(t, store, sharedRoot, nil)
	chainB64B := make([]string, len(chainDERB))
	for i, der := range chainDERB {
		chainB64B[i] = base64.StdEncoding.EncodeToString(der)
	}
	reqB, _ := json.Marshal(EnrollRequest{
		DeviceID:         "victim-label",
		CSR:              base64.StdEncoding.EncodeToString(csrDERB),
		AttestationChain: chainB64B,
	})
	recB := httptest.NewRecorder()
	enrollHandler.ServeHTTP(recB, httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(reqB)))
	if recB.Code != http.StatusCreated {
		t.Fatalf("expected second genuine device to enroll under its own identity, got %d: %s", recB.Code, recB.Body.String())
	}

	var respB EnrollResponse
	if err := json.Unmarshal(recB.Body.Bytes(), &respB); err != nil {
		t.Fatalf("failed to parse second enroll response: %v", err)
	}

	parsedCSRA, err := x509.ParseCertificateRequest(csrDERA)
	if err != nil {
		t.Fatalf("failed to parse CSR A: %v", err)
	}
	identityA, err := attestation.PublicKeyFingerprint(parsedCSRA.PublicKey)
	if err != nil {
		t.Fatalf("failed to derive identity A: %v", err)
	}
	if respB.DeviceIdentity == identityA {
		t.Fatal("second device must not receive the first device's identity")
	}
	if strings.Contains(respB.DeviceIdentity, "victim-label") {
		t.Fatal("identity must be derived from the key, not from the label")
	}
}

func TestEnrollHandlerDevModeEmptyAttestation(t *testing.T) {
	caInstance, caPEM, _, err := ca.GenerateCA("Dev Test CA", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	store := storage.NewMemoryChallengeStore()
	deviceRepo := storage.NewMemoryDeviceRepo()

	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "dev-mock-simple"},
	}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, devKey)

	// 1. In DevelopmentPolicy, empty attestation chain must succeed
	devVerifier := attestation.MustNewVerifier(nil, attestation.DevelopmentPolicy())
	devEnrollHandler := NewEnrollHandler(caInstance, string(caPEM), devVerifier, store, deviceRepo, 24*time.Hour)

	reqBody := EnrollRequest{
		DeviceID:         "dev-mock-simple",
		CSR:              base64.StdEncoding.EncodeToString(csrDER),
		AttestationChain: nil, // empty attestation chain
	}
	reqBytes, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(reqBytes))
	rec := httptest.NewRecorder()
	devEnrollHandler.ServeHTTP(rec, httpReq)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created in dev mode without attestation, got %d: %s", rec.Code, rec.Body.String())
	}

	var enrollResp EnrollResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &enrollResp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if enrollResp.ClientCertificate == "" {
		t.Fatal("expected client certificate")
	}

	// 2. In DefaultStrictPolicy, empty attestation chain must fail with 400 Bad Request
	strictVerifier := attestation.MustNewVerifier(nil, attestation.DefaultStrictPolicy())
	strictEnrollHandler := NewEnrollHandler(caInstance, string(caPEM), strictVerifier, store, deviceRepo, 24*time.Hour)

	strictReq := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(reqBytes))
	strictRec := httptest.NewRecorder()
	strictEnrollHandler.ServeHTTP(strictRec, strictReq)

	if strictRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request in strict mode without attestation, got %d", strictRec.Code)
	}
}

func TestEnrollHandlerInputValidation(t *testing.T) {
	store := storage.NewMemoryChallengeStore()
	deviceRepo := storage.NewMemoryDeviceRepo()

	_, csrDER, chainDER, _ := buildMockAttestationChain(t, store, nil, nil)
	enrollHandler := newTestEnrollHandler(t, deviceRepo, store, chainDER)
	chainB64 := make([]string, len(chainDER))
	for i, der := range chainDER {
		chainB64[i] = base64.StdEncoding.EncodeToString(der)
	}

	// Invalid label characters must be rejected with 400
	badReq, _ := json.Marshal(EnrollRequest{
		DeviceID:         "bad label with spaces;$(rm -rf)",
		CSR:              base64.StdEncoding.EncodeToString(csrDER),
		AttestationChain: chainB64,
	})
	rec := httptest.NewRecorder()
	enrollHandler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(badReq)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid label, got %d: %s", rec.Code, rec.Body.String())
	}

	// Oversized body must be rejected with 400
	oversized := bytes.Repeat([]byte("A"), maxEnrollBodyBytes+1024)
	rec2 := httptest.NewRecorder()
	enrollHandler.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(oversized)))
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized body, got %d", rec2.Code)
	}
}
