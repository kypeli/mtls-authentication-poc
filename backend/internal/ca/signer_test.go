package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

func TestGenerateCAAndSignCSR(t *testing.T) {
	caInstance, caPEM, _, err := GenerateCA("Test Root CA", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}
	if len(caPEM) == 0 {
		t.Fatal("caPEM is empty")
	}

	// Create client key and PKCS#10 CSR
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "device-test-123",
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, clientKey)
	if err != nil {
		t.Fatalf("CreateCertificateRequest failed: %v", err)
	}

	// Sign CSR
	deviceID := "device-test-123"
	ttl := 7 * 24 * time.Hour
	clientCert, clientPEM, err := caInstance.SignCSR(csrDER, deviceID, ttl)
	if err != nil {
		t.Fatalf("SignCSR failed: %v", err)
	}

	if len(clientPEM) == 0 {
		t.Fatal("clientPEM is empty")
	}

	if clientCert.Subject.CommonName != deviceID {
		t.Errorf("expected CommonName %s, got %s", deviceID, clientCert.Subject.CommonName)
	}

	if len(clientCert.URIs) != 1 || clientCert.URIs[0].String() != "urn:device:"+deviceID {
		t.Errorf("expected SAN URI urn:device:%s, got %v", deviceID, clientCert.URIs)
	}

	// Verify the client certificate using the CA
	roots := NewCertPoolFromCert(caInstance.Certificate)
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if _, err := clientCert.Verify(opts); err != nil {
		t.Fatalf("client cert verification failed against CA root: %v", err)
	}
}

func TestSignCSRInvalidSignature(t *testing.T) {
	caInstance, _, _, err := GenerateCA("Test Root CA", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "device-bad"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, clientKey)
	if err != nil {
		t.Fatalf("CreateCertificateRequest failed: %v", err)
	}

	// Tamper with the CSR DER bytes (corrupting signature)
	csrDER[len(csrDER)-5] ^= 0xFF

	_, _, err = caInstance.SignCSR(csrDER, "device-bad", 24*time.Hour)
	if err == nil {
		t.Fatal("expected error on tampered CSR signature, got nil")
	}
}
