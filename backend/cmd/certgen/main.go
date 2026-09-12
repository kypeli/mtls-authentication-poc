package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/kypeli/mtls-poc/backend/internal/ca"
)

func main() {
	outDir := flag.String("out-dir", "certs", "Directory where certificates will be written")
	caCN := flag.String("ca-cn", "Hardware mTLS PoC Root CA", "Common Name for Root CA")
	serverCN := flag.String("server-cn", "localhost", "Common Name for Server TLS certificate")
	force := flag.Bool("force", false, "Overwrite existing certificate and key files")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create cert directory %s: %v\n", *outDir, err)
		os.Exit(1)
	}

	caKeyPath := filepath.Join(*outDir, "ca.key")
	caCertPath := filepath.Join(*outDir, "ca.crt")
	serverKeyPath := filepath.Join(*outDir, "server.key")
	serverCertPath := filepath.Join(*outDir, "server.crt")

	if !*force {
		if fileExists(caKeyPath) || fileExists(caCertPath) || fileExists(serverKeyPath) || fileExists(serverCertPath) {
			fmt.Printf("Certificates already exist in %s. Use -force to overwrite.\n", *outDir)
			return
		}
	}

	// 1. Generate Root CA
	fmt.Printf("Generating Root CA (%s)...\n", *caCN)
	caInstance, caCertPEM, caKeyPEM, err := ca.GenerateCA(*caCN, 10*365*24*time.Hour)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate Root CA: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(caKeyPath, caKeyPEM, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write %s: %v\n", caKeyPath, err)
		os.Exit(1)
	}
	if err := os.WriteFile(caCertPath, caCertPEM, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write %s: %v\n", caCertPath, err)
		os.Exit(1)
	}

	// 2. Generate Server TLS Key and Certificate signed by CA
	fmt.Printf("Generating Server TLS Certificate for %s (SAN: localhost, 127.0.0.1, 10.0.2.2, ::1)...\n", *serverCN)
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate server key: %v\n", err)
		os.Exit(1)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serverSerial, _ := rand.Int(rand.Reader, serialNumberLimit)

	serverTemplate := x509.Certificate{
		SerialNumber: serverSerial,
		Subject: pkix.Name{
			CommonName:   *serverCN,
			Organization: []string{"Hardware mTLS Server"},
		},
		DNSNames: []string{
			"localhost",
			"android.local",
		},
		IPAddresses:           getHostSANIPs(),
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caInstance.Certificate, &serverKey.PublicKey, caInstance.PrivateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create server certificate: %v\n", err)
		os.Exit(1)
	}

	serverCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertDER,
	})

	serverKeyDER, _ := x509.MarshalECPrivateKey(serverKey)
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: serverKeyDER,
	})

	if err := os.WriteFile(serverKeyPath, serverKeyPEM, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write %s: %v\n", serverKeyPath, err)
		os.Exit(1)
	}
	if err := os.WriteFile(serverCertPath, serverCertPEM, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write %s: %v\n", serverCertPath, err)
		os.Exit(1)
	}

	fmt.Printf("Certificates generated successfully in %s:\n", *outDir)
	fmt.Printf("  • CA Key:      %s\n", caKeyPath)
	fmt.Printf("  • CA Cert:     %s\n", caCertPath)
	fmt.Printf("  • Server Key:  %s\n", serverKeyPath)
	fmt.Printf("  • Server Cert: %s\n", serverCertPath)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func getHostSANIPs() []net.IP {
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
