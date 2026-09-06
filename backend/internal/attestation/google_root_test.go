package attestation

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestEmbeddedGoogleRootCertificates(t *testing.T) {
	for name, pemStr := range map[string]string{
		"GoogleHardwareAttestationRootRSA": GoogleHardwareAttestationRootRSA,
		"GoogleHardwareAttestationRootEC":  GoogleHardwareAttestationRootEC,
	} {
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			t.Fatalf("%s failed PEM decoding", name)
		}
		if block.Type != "CERTIFICATE" {
			t.Fatalf("%s has unexpected PEM block type: %s", name, block.Type)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("%s failed x509.ParseCertificate: %v", name, err)
		}

		if !cert.IsCA {
			t.Errorf("%s is not marked as a CA", name)
		}

		if time.Now().After(cert.NotAfter) {
			t.Errorf("%s has expired: %s", name, cert.NotAfter)
		}

		t.Logf("%s parsed successfully: Subject=%s, NotAfter=%s, SigAlg=%s",
			name, cert.Subject, cert.NotAfter, cert.SignatureAlgorithm)
	}

	pool, err := NewGoogleRootCertPool()
	if err != nil {
		t.Fatalf("NewGoogleRootCertPool failed: %v", err)
	}
	if pool == nil {
		t.Fatal("NewGoogleRootCertPool returned nil pool")
	}
}

func TestCorruptedGoogleRootFailsLoudly(t *testing.T) {
	// Temporarily inject a corrupted root to verify failure
	original := DefaultGoogleRootPEMs
	defer func() { DefaultGoogleRootPEMs = original }()

	DefaultGoogleRootPEMs = []string{"not-a-valid-pem"}
	if _, err := NewGoogleRootCertPool(); err == nil {
		t.Fatal("expected NewGoogleRootCertPool to fail on corrupted PEM, got nil error")
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected MustNewGoogleRootCertPool to panic on corrupted root, but it did not")
		}
	}()
	_ = MustNewGoogleRootCertPool()
}
