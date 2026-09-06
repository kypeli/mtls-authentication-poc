package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kypeli/mtls-poc/backend/internal/attestation"
	"github.com/kypeli/mtls-poc/backend/internal/ca"
	"github.com/kypeli/mtls-poc/backend/internal/config"
	"github.com/kypeli/mtls-poc/backend/internal/handlers"
	"github.com/kypeli/mtls-poc/backend/internal/middleware"
	"github.com/kypeli/mtls-poc/backend/internal/storage"
)

func main() {
	cfg := config.LoadConfig()

	log.Printf("==========================================================")
	log.Printf(" Starting Hardware-Backed mTLS PoC Backend")
	log.Printf(" Enroll HTTPS Port: %s (Standard TLS)", cfg.EnrollPort)
	log.Printf(" mTLS 1.3 Port:    %s", cfg.MtlsPort)
	log.Printf(" Dev Mode:         %v", cfg.DevMode)
	log.Printf(" Cert Directory:   %s", cfg.CertDir)
	log.Printf("==========================================================")

	// Ensure cert directory exists and bootstrap certs if necessary
	if err := ensureCertificates(cfg); err != nil {
		log.Fatalf("Failed to initialize certificates: %v", err)
	}

	// 1. Load CA
	caInstance, err := ca.LoadCA(cfg.CaCertPath, cfg.CaKeyPath)
	if err != nil {
		log.Fatalf("Failed to load CA: %v", err)
	}
	caPEMBytes, err := os.ReadFile(cfg.CaCertPath)
	if err != nil {
		log.Fatalf("Failed to read CA certificate PEM: %v", err)
	}
	caPEM := string(caPEMBytes)

	// 2. Storage
	challengeStore := storage.NewMemoryChallengeStore()
	deviceRepo := storage.NewMemoryDeviceRepo()

	// 3. Attestation policy
	policy := attestation.DefaultStrictPolicy()
	if cfg.DevMode {
		log.Printf("⚠️  DEV_MODE enabled: using lenient attestation policy for local/emulator testing")
		policy = attestation.DevelopmentPolicy()
	}
	verifier, err := attestation.NewVerifier(nil, policy)
	if err != nil {
		log.Fatalf("Failed to initialize attestation verifier: %v", err)
	}

	// 4. Setup Enrollment HTTPS Server (Standard TLS, Port 8080)
	enrollCert, err := tls.LoadX509KeyPair(cfg.EnrollCertPath, cfg.EnrollKeyPath)
	if err != nil {
		log.Fatalf("Failed to load enrollment TLS keypair: %v", err)
	}

	enrollTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{enrollCert},
		ClientAuth:   tls.NoClientCert, // Standard one-way TLS: client does NOT require/provide a client cert
		MinVersion:   tls.VersionTLS12, // Standard Android TLS 1.2+ support
	}

	enrollMux := http.NewServeMux()
	enrollMux.Handle("/api/v1/enroll/challenge", handlers.NewChallengeHandler(challengeStore, cfg.ChallengeTTL))
	enrollMux.Handle("/api/v1/enroll", handlers.NewEnrollHandler(
		caInstance,
		caPEM,
		verifier,
		challengeStore,
		deviceRepo,
		cfg.ClientCertTTL,
	))

	enrollServer := &http.Server{
		Addr:         cfg.EnrollPort,
		Handler:      requestLogger(enrollMux, "ENROLL"),
		TLSConfig:    enrollTLSConfig,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	// 5. Setup mTLS 1.3 Protected Server (Port 8443)
	serverCert, err := tls.LoadX509KeyPair(cfg.ServerCertPath, cfg.ServerKeyPath)
	if err != nil {
		log.Fatalf("Failed to load server TLS keypair: %v", err)
	}

	clientCaPool := ca.NewCertPoolFromCert(caInstance.Certificate)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCaPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}

	mtlsMux := http.NewServeMux()
	pingHandler := handlers.NewProtectedPingHandler()
	mtlsMux.Handle("/api/v1/protected/ping", middleware.MtlsAuthMiddleware(deviceRepo)(pingHandler))

	mtlsServer := &http.Server{
		Addr:         cfg.MtlsPort,
		Handler:      requestLogger(mtlsMux, "MTLS"),
		TLSConfig:    tlsConfig,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	// Start servers in goroutines
	errChan := make(chan error, 2)

	go func() {
		log.Printf("🔒 Enrollment HTTPS (standard TLS) listener started on %s", cfg.EnrollPort)
		if err := enrollServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- fmt.Errorf("enrollment server failed: %w", err)
		}
	}()

	go func() {
		log.Printf("🔒 Mutual TLS 1.3 listener started on %s (RequireAndVerifyClientCert)", cfg.MtlsPort)
		// TLS listener uses the pre-configured tlsConfig on mtlsServer
		if err := mtlsServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- fmt.Errorf("mTLS server failed: %w", err)
		}
	}()

	// Handle shutdown gracefully
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-quit:
		log.Printf("Received signal %v. Initiating graceful shutdown...", sig)
	case err := <-errChan:
		log.Printf("Server startup error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := enrollServer.Shutdown(ctx); err != nil {
		log.Printf("Error shutting down enrollment server: %v", err)
	}
	if err := mtlsServer.Shutdown(ctx); err != nil {
		log.Printf("Error shutting down mTLS server: %v", err)
	}

	log.Printf("Backend stopped cleanly.")
}

func ensureCertificates(cfg *config.Config) error {
	if err := os.MkdirAll(cfg.CertDir, 0755); err != nil {
		return fmt.Errorf("failed to create certs directory: %w", err)
	}

	caExists := fileExists(cfg.CaCertPath) && fileExists(cfg.CaKeyPath)
	serverExists := fileExists(cfg.ServerCertPath) && fileExists(cfg.ServerKeyPath)

	if caExists && serverExists {
		return nil
	}

	log.Printf("Certificates missing in %s; bootstrapping local root CA and server TLS certificates...", cfg.CertDir)

	caInstance, caCertPEM, caKeyPEM, err := ca.GenerateCA("Hardware mTLS PoC Root CA", 10*365*24*time.Hour)
	if err != nil {
		return fmt.Errorf("failed to generate Root CA: %w", err)
	}

	if err := os.WriteFile(cfg.CaKeyPath, caKeyPEM, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(cfg.CaCertPath, caCertPEM, 0644); err != nil {
		return err
	}

	// Generate Server TLS key & cert signed by CA
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serverSerial, _ := rand.Int(rand.Reader, serialNumberLimit)

	serverTemplate := x509.Certificate{
		SerialNumber: serverSerial,
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"Hardware mTLS Server"},
		},
		DNSNames: []string{
			"localhost",
			"android.local",
		},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("10.0.2.2"), // Android emulator host alias
			net.ParseIP("::1"),
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caInstance.Certificate, &serverKey.PublicKey, caInstance.PrivateKey)
	if err != nil {
		return err
	}

	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
	serverKeyDER, _ := x509.MarshalECPrivateKey(serverKey)
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyDER})

	if err := os.WriteFile(cfg.ServerKeyPath, serverKeyPEM, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(cfg.ServerCertPath, serverCertPEM, 0644); err != nil {
		return err
	}

	log.Printf("Successfully bootstrapped local CA and Server TLS certificates in %s", cfg.CertDir)
	return nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func requestLogger(next http.Handler, tag string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[%s] %s %s from %s in %v", tag, r.Method, r.URL.Path, r.RemoteAddr, time.Since(start))
	})
}
