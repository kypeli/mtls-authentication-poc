package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// BootstrapPaths identifies the certificate and key files managed by a bootstrap.
type BootstrapPaths struct {
	CaCertPath     string
	CaKeyPath      string
	ServerCertPath string
	ServerKeyPath  string
}

// BootstrapOptions configures certificate generation for a local Root CA and
// server TLS certificate pair.
type BootstrapOptions struct {
	Paths          BootstrapPaths
	CaCN           string
	ServerCN       string
	CaValidity     time.Duration
	ServerValidity time.Duration
}

// BootstrapCertificates generates a self-signed Root CA and a server TLS
// certificate signed by it when they are missing. It refuses to overwrite any
// existing file: a partial set (e.g. a committed CA certificate without its
// key) must be resolved explicitly, because regenerating the CA silently
// invalidates every previously issued client certificate and any client that
// pinned or trusted the old CA.
func BootstrapCertificates(opts BootstrapOptions) (BootstrapPaths, error) {
	p := opts.Paths

	if err := os.MkdirAll(dirOf(p.CaCertPath), 0755); err != nil {
		return p, fmt.Errorf("failed to create certs directory: %w", err)
	}
	if err := os.MkdirAll(dirOf(p.ServerCertPath), 0755); err != nil {
		return p, fmt.Errorf("failed to create certs directory: %w", err)
	}

	existing := []string{}
	for _, path := range []string{p.CaCertPath, p.CaKeyPath, p.ServerCertPath, p.ServerKeyPath} {
		if fileExists(path) {
			existing = append(existing, path)
		}
	}

	if len(existing) == 4 {
		return p, nil
	}
	if len(existing) > 0 {
		return p, fmt.Errorf(
			"refusing to bootstrap certificates: some files already exist (%v). "+
				"Delete the stale files explicitly to regenerate", existing)
	}

	if opts.CaValidity == 0 {
		opts.CaValidity = 10 * 365 * 24 * time.Hour
	}
	if opts.ServerValidity == 0 {
		opts.ServerValidity = 5 * 365 * 24 * time.Hour
	}
	if opts.CaCN == "" {
		opts.CaCN = "Hardware mTLS PoC Root CA"
	}
	if opts.ServerCN == "" {
		opts.ServerCN = "localhost"
	}

	caInstance, caCertPEM, caKeyPEM, err := GenerateCA(opts.CaCN, opts.CaValidity)
	if err != nil {
		return p, fmt.Errorf("failed to generate Root CA: %w", err)
	}

	if err := os.WriteFile(p.CaKeyPath, caKeyPEM, 0600); err != nil {
		return p, err
	}
	if err := os.WriteFile(p.CaCertPath, caCertPEM, 0644); err != nil {
		return p, err
	}

	// Generate Server TLS key & cert signed by the CA
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return p, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serverSerial, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return p, err
	}

	serverTemplate := x509.Certificate{
		SerialNumber: serverSerial,
		Subject: pkix.Name{
			CommonName:   opts.ServerCN,
			Organization: []string{"Hardware mTLS Server"},
		},
		DNSNames: []string{
			"localhost",
			"android.local",
		},
		IPAddresses:           HostSANIPs(),
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(opts.ServerValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caInstance.Certificate, &serverKey.PublicKey, caInstance.PrivateKey)
	if err != nil {
		return p, err
	}

	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
	serverKeyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return p, err
	}
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER})

	if err := os.WriteFile(p.ServerKeyPath, serverKeyPEM, 0600); err != nil {
		return p, err
	}
	if err := os.WriteFile(p.ServerCertPath, serverCertPEM, 0644); err != nil {
		return p, err
	}

	return p, nil
}

// HostSANIPs returns the SAN IP addresses for the server certificate: loopback,
// the Android emulator host alias, and every non-loopback IPv4 address.
func HostSANIPs() []net.IP {
	ips := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("10.0.2.2"), // Android emulator host alias
		net.ParseIP("::1"),
	}
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok {
					if ip4 := ipNet.IP.To4(); ip4 != nil {
						ips = append(ips, ip4)
					}
				}
			}
		}
	}
	return ips
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
