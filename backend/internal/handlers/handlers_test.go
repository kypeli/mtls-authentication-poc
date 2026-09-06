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
	"math/big"
	"net/http"
	"net/http/httptest"
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

func TestEnrollHandlerAndMtlsFlow(t *testing.T) {
	caInstance, caPEM, _, err := ca.GenerateCA("Test CA Root", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	store := storage.NewMemoryChallengeStore()
	deviceRepo := storage.NewMemoryDeviceRepo()

	// Generate synthetic attestation chain
	challengeB64, _, err := store.GenerateAndStoreChallenge(60 * time.Second)
	if err != nil {
		t.Fatalf("failed to generate challenge: %v", err)
	}
	challengeBytes, _ := base64.StdEncoding.DecodeString(challengeB64)

	// Build mock attestation root & chain
	attestRootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attestRootTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Mock Attest Root"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	attestRootDER, _ := x509.CreateCertificate(rand.Reader, &attestRootTemplate, &attestRootTemplate, &attestRootKey.PublicKey, attestRootKey)
	attestRootCert, _ := x509.ParseCertificate(attestRootDER)

	// Device key & CSR
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "dev-mock-001"},
	}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, devKey)

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

	rootPool := x509.NewCertPool()
	rootPool.AddCert(attestRootCert)
	verifier := attestation.MustNewVerifier(rootPool, attestation.DefaultStrictPolicy())

	enrollHandler := NewEnrollHandler(caInstance, string(caPEM), verifier, store, deviceRepo, 7*24*time.Hour)

	enrollReqBody := EnrollRequest{
		DeviceID:         "dev-mock-001",
		Challenge:        challengeB64,
		CSR:              base64.StdEncoding.EncodeToString(csrDER),
		AttestationChain: []string{
			base64.StdEncoding.EncodeToString(leafDER),
			base64.StdEncoding.EncodeToString(attestRootDER),
		},
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

	// Verify device recorded in device repo
	if !deviceRepo.IsDeviceActive("dev-mock-001") {
		t.Fatal("device should be registered and active")
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

	// 2. Authenticated request with peer certificate -> 200 OK
	authReq := httptest.NewRequest(http.MethodGet, "/api/v1/protected/ping", nil)
	authReq.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{
			{
				Subject: pkix.Name{
					CommonName: "dev-mock-001",
				},
				SerialNumber: big.NewInt(999),
			},
		},
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
	if pingResp.DeviceID != "dev-mock-001" || pingResp.Status != "ok" {
		t.Fatalf("unexpected ping response: %+v", pingResp)
	}

	// 3. Revoke device and test -> 403 Forbidden
	_ = deviceRepo.RevokeDevice("dev-mock-001")
	revokedRec := httptest.NewRecorder()
	protectedPipeline.ServeHTTP(revokedRec, authReq)
	if revokedRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for revoked device, got %d", revokedRec.Code)
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
