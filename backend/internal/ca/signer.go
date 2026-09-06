package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"time"
)

// CA represents an in-process Certificate Authority capable of signing device CSRs.
type CA struct {
	Certificate *x509.Certificate
	PrivateKey  *ecdsa.PrivateKey
}

// NewCA constructs a CA instance with the provided certificate and private key.
func NewCA(cert *x509.Certificate, key *ecdsa.PrivateKey) *CA {
	return &CA{
		Certificate: cert,
		PrivateKey:  key,
	}
}

// GenerateCA creates a new self-signed root CA with ECDSA P-256 key.
func GenerateCA(commonName string, validity time.Duration) (*CA, []byte, []byte, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Hardware mTLS PoC"},
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse generated CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal CA private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	ca := &CA{
		Certificate: parsedCert,
		PrivateKey:  privKey,
	}

	return ca, certPEM, keyPEM, nil
}

// LoadCA loads a CA certificate and private key from PEM files on disk.
func LoadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate file: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA private key file: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("failed to decode CA key PEM")
	}

	var privKey *ecdsa.PrivateKey
	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		privKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err == nil {
			var ok bool
			privKey, ok = parsed.(*ecdsa.PrivateKey)
			if !ok {
				return nil, errors.New("private key is not an ECDSA key")
			}
		}
	default:
		return nil, fmt.Errorf("unsupported key block type: %s", keyBlock.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	return &CA{
		Certificate: cert,
		PrivateKey:  privKey,
	}, nil
}

// SignCSR parses a PKCS#10 CSR, cryptographically verifies its signature,
// and mints an X.509 client certificate anchored to this CA.
func (c *CA) SignCSR(csrDER []byte, deviceID string, ttl time.Duration) (*x509.Certificate, []byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate request: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("invalid CSR signature: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	deviceURI, err := url.Parse(fmt.Sprintf("urn:device:%s", deviceID))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse device URI: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   deviceID,
			Organization: []string{"Hardware mTLS Client"},
		},
		URIs:                  []*url.URL{deviceURI},
		NotBefore:             now.Add(-1 * time.Minute), // Clock drift buffer
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, c.Certificate, csr.PublicKey, c.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign client certificate: %w", err)
	}

	parsedClientCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse issued client certificate: %w", err)
	}

	clientCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return parsedClientCert, clientCertPEM, nil
}
