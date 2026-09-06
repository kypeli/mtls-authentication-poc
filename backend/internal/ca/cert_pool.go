package ca

import (
	"crypto/x509"
	"fmt"
	"os"
)

// NewCertPoolFromCert returns an *x509.CertPool containing the provided certificate.
func NewCertPoolFromCert(cert *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}

// NewCertPoolFromPEM parses PEM-encoded certificates into an *x509.CertPool.
func NewCertPoolFromPEM(pemBytes []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("failed to append any certificates from PEM bytes")
	}
	return pool, nil
}

// NewCertPoolFromFile reads a PEM file from disk and populates an *x509.CertPool.
func NewCertPoolFromFile(certPath string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert file %s: %w", certPath, err)
	}
	return NewCertPoolFromPEM(pemBytes)
}
