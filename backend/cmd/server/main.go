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

	attachTLSInspectors(enrollTLSConfig, "ENROLL")
	enrollServer := &http.Server{
		Addr:         cfg.EnrollPort,
		Handler:      requestLogger(enrollMux, "ENROLL"),
		TLSConfig:    enrollTLSConfig,
		ConnState:    connStateLogger("ENROLL"),
		ErrorLog:     log.New(os.Stderr, "[ENROLL-ERR] ", log.LstdFlags),
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

	attachTLSInspectors(tlsConfig, "MTLS")
	mtlsMux := http.NewServeMux()
	pingHandler := handlers.NewProtectedPingHandler()
	mtlsMux.Handle("/api/v1/protected/ping", middleware.MtlsAuthMiddleware(deviceRepo)(pingHandler))

	mtlsServer := &http.Server{
		Addr:         cfg.MtlsPort,
		Handler:      requestLogger(mtlsMux, "MTLS"),
		TLSConfig:    tlsConfig,
		ConnState:    connStateLogger("MTLS"),
		ErrorLog:     log.New(os.Stderr, "[MTLS-ERR] ", log.LstdFlags),
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
		IPAddresses:           getHostSANIPs(),
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

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func connStateLogger(tag string) func(net.Conn, http.ConnState) {
	return func(conn net.Conn, state http.ConnState) {
		remote := "unknown"
		if conn != nil && conn.RemoteAddr() != nil {
			remote = conn.RemoteAddr().String()
		}
		log.Printf("[%s-TCP] Connection %s state -> %s", tag, remote, state)
	}
}

func attachTLSInspectors(cfg *tls.Config, tag string) {
	origGetConfig := cfg.GetConfigForClient
	cfg.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		remoteAddr := "unknown"
		if chi.Conn != nil && chi.Conn.RemoteAddr() != nil {
			remoteAddr = chi.Conn.RemoteAddr().String()
		}
		versions := make([]string, 0, len(chi.SupportedVersions))
		for _, v := range chi.SupportedVersions {
			versions = append(versions, tls.VersionName(v))
		}
		log.Printf("[%s-TLS] 🤝 ClientHello from %s: SNI=%q, ALPN=%v, Versions=%v, CiphersCount=%d",
			tag, remoteAddr, chi.ServerName, chi.SupportedProtos, versions, len(chi.CipherSuites))

		if origGetConfig != nil {
			return origGetConfig(chi)
		}
		return nil, nil
	}

	origVerify := cfg.VerifyConnection
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		log.Printf("[%s-TLS] 🔒 Handshake completed: Version=%s, Cipher=%s, ALPN=%q, SNI=%q, Resumed=%v, PeerCerts=%d",
			tag,
			tls.VersionName(cs.Version),
			tls.CipherSuiteName(cs.CipherSuite),
			cs.NegotiatedProtocol,
			cs.ServerName,
			cs.DidResume,
			len(cs.PeerCertificates),
		)
		for i, cert := range cs.PeerCertificates {
			log.Printf("[%s-TLS]   ├─ PeerCert[%d]: SubjectCN=%q, Serial=%s, IssuerCN=%q, NotAfter=%s",
				tag, i, cert.Subject.CommonName, cert.SerialNumber.String(), cert.Issuer.CommonName, cert.NotAfter.Format(time.RFC3339))
		}
		if origVerify != nil {
			return origVerify(cs)
		}
		return nil
	}
}

type responseRecorder struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (rec *responseRecorder) WriteHeader(code int) {
	rec.statusCode = code
	rec.ResponseWriter.WriteHeader(code)
}

func (rec *responseRecorder) Write(b []byte) (int, error) {
	if rec.statusCode == 0 {
		rec.statusCode = http.StatusOK
	}
	n, err := rec.ResponseWriter.Write(b)
	rec.bytesWritten += int64(n)
	return n, err
}

func (rec *responseRecorder) Flush() {
	if f, ok := rec.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func requestLogger(next http.Handler, tag string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		tlsInfo := "none"
		if r.TLS != nil {
			tlsInfo = fmt.Sprintf("ver=%s, cipher=%s, client_certs=%d",
				tls.VersionName(r.TLS.Version),
				tls.CipherSuiteName(r.TLS.CipherSuite),
				len(r.TLS.PeerCertificates),
			)
		}
		ua := r.UserAgent()
		if ua == "" {
			ua = "-"
		}
		log.Printf("[%s-HTTP] --> %s %s from %s (Proto: %s, Host: %s, UA: %s, TLS: %s)",
			tag, r.Method, r.URL.Path, r.RemoteAddr, r.Proto, r.Host, ua, tlsInfo)

		rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rec, r)

		log.Printf("[%s-HTTP] <-- %d %s for %s in %v (%d bytes)",
			tag, rec.statusCode, r.URL.Path, r.RemoteAddr, time.Since(start), rec.bytesWritten)
	})
}
