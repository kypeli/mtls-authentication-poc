package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kypeli/mtls-poc/backend/internal/attestation"
	"github.com/kypeli/mtls-poc/backend/internal/storage"
)

// issueClientCert mints a self-signed client certificate for the given key with
// the provided CN and serial, mimicking the CA-issued client certificate shape.
func issueClientCert(t *testing.T, key *ecdsa.PrivateKey, cn string, serial int64) *x509.Certificate {
	t.Helper()
	template := x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create client cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse client cert: %v", err)
	}
	return cert
}

func mustFingerprint(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	id, err := attestation.PublicKeyFingerprint(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to derive fingerprint: %v", err)
	}
	return id
}

func requestWithCert(cert *x509.Certificate) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	return req
}

func TestMtlsAuthRejectsMissingCertificate(t *testing.T) {
	repo := storage.NewMemoryDeviceRepo()
	handler := MtlsAuthMiddleware(repo)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be reached")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without client certificate, got %d", rec.Code)
	}
}

func TestMtlsAuthIdentityBindingAndRevocation(t *testing.T) {
	repo := storage.NewMemoryDeviceRepo()

	// Genuine device key: identity is derived from its public key
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	identity := mustFingerprint(t, deviceKey)

	record := storage.DeviceRecord{
		Identity:   identity,
		Label:      "device-label",
		CertSerial: "1234",
		EnrolledAt: time.Now(),
	}
	if err := repo.RegisterDevice(record); err != nil {
		t.Fatalf("failed to register device: %v", err)
	}

	var served *DeviceIdentity
	handler := MtlsAuthMiddleware(repo)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served, _ = GetDeviceIdentity(r.Context())
	}))

	// 1. Valid certificate: identity bound to the attested key, serial current -> 200
	goodCert := issueClientCert(t, deviceKey, identity, 1234)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, requestWithCert(goodCert))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid client cert, got %d: %s", rec.Code, rec.Body.String())
	}
	if served == nil || served.Identity != identity || served.Label != "device-label" {
		t.Fatalf("unexpected identity in context: %+v", served)
	}

	// 2. CN does not match the certificate's public key fingerprint -> 403
	attackerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spoofedCert := issueClientCert(t, attackerKey, identity, 4321)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, requestWithCert(spoofedCert))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when CN does not match key fingerprint, got %d", rec.Code)
	}

	// 3. Unknown identity -> 403
	unknownCert := issueClientCert(t, attackerKey, mustFingerprint(t, attackerKey), 4322)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, requestWithCert(unknownCert))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unknown identity, got %d", rec.Code)
	}

	// 4. Stale serial (certificate superseded by re-enrollment) -> 403
	rotatedRecord := record
	rotatedRecord.CertSerial = "5678"
	if err := repo.RegisterDevice(rotatedRecord); err != nil {
		t.Fatalf("failed to rotate serial: %v", err)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, requestWithCert(goodCert))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for stale certificate serial, got %d", rec.Code)
	}

	// 5. Revoked serial -> 403
	currentCert := issueClientCert(t, deviceKey, identity, 5678)
	if err := repo.RevokeSerial("5678"); err != nil {
		t.Fatalf("failed to revoke serial: %v", err)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, requestWithCert(currentCert))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for revoked serial, got %d", rec.Code)
	}

	// 6. Revoked identity -> 403
	if err := repo.RegisterDevice(record); err != nil {
		t.Fatalf("failed to restore record: %v", err)
	}
	freshCert := issueClientCert(t, deviceKey, identity, 1234)
	if err := repo.RevokeDevice(identity); err != nil {
		t.Fatalf("failed to revoke device: %v", err)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, requestWithCert(freshCert))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for revoked identity, got %d", rec.Code)
	}
}
