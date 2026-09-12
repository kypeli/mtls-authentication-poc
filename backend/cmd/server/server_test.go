package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/kypeli/mtls-poc/backend/internal/attestation"
	"github.com/kypeli/mtls-poc/backend/internal/ca"
	"github.com/kypeli/mtls-poc/backend/internal/handlers"
	"github.com/kypeli/mtls-poc/backend/internal/middleware"
	"github.com/kypeli/mtls-poc/backend/internal/storage"
)

// memListener implements in-memory net.Listener using net.Pipe for zero-sandbox-restriction testing.
type memListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newMemListener() *memListener {
	return &memListener{
		conns:  make(chan net.Conn),
		closed: make(chan struct{}),
	}
}

func (m *memListener) Accept() (net.Conn, error) {
	select {
	case <-m.closed:
		return nil, errors.New("listener closed")
	case c, ok := <-m.conns:
		if !ok {
			return nil, errors.New("listener closed")
		}
		return c, nil
	}
}

func (m *memListener) Close() error {
	m.once.Do(func() {
		close(m.closed)
	})
	return nil
}

func (m *memListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443}
}

func (m *memListener) Dial() (net.Conn, error) {
	select {
	case <-m.closed:
		return nil, errors.New("listener closed")
	default:
	}

	client, server := net.Pipe()
	m.conns <- server
	return client, nil
}

func TestEndToEndEnrollmentAndMtls(t *testing.T) {
	// 1. Initialize CA and storage
	caInstance, caPEM, _, err := ca.GenerateCA("E2E Root CA", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	challengeStore := storage.NewMemoryChallengeStore()
	deviceRepo := storage.NewMemoryDeviceRepo()
	policy := attestation.DevelopmentPolicy()
	verifier := attestation.MustNewVerifier(nil, policy)

	// 2. Setup Server TLS Certificate and CA Pool
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverCertDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caInstance.Certificate, &serverKey.PublicKey, caInstance.PrivateKey)
	if err != nil {
		t.Fatalf("failed to create server cert: %v", err)
	}
	serverTlsCert := tls.Certificate{
		Certificate: [][]byte{serverCertDER},
		PrivateKey:  serverKey,
	}

	serverCaPool := x509.NewCertPool()
	serverCaPool.AddCert(caInstance.Certificate)

	// 3. Setup In-Memory Enrollment Server (Standard TLS 1.2+ / NoClientCert)
	enrollMux := http.NewServeMux()
	enrollMux.Handle("/api/v1/enroll/challenge", handlers.NewChallengeHandler(challengeStore, 60*time.Second))
	enrollMux.Handle("/api/v1/enroll", handlers.NewEnrollHandler(
		caInstance,
		string(caPEM),
		verifier,
		challengeStore,
		deviceRepo,
		7*24*time.Hour,
	))

	enrollTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverTlsCert},
		ClientAuth:   tls.NoClientCert, // Standard one-way TLS
		MinVersion:   tls.VersionTLS12,
	}

	enrollMemListener := newMemListener()
	enrollListener := tls.NewListener(enrollMemListener, enrollTLSConfig)
	enrollServer := &http.Server{Handler: enrollMux}
	go func() { _ = enrollServer.Serve(enrollListener) }()
	defer func() { _ = enrollServer.Close() }()

	// Standard HTTPS client without client certificate
	enrollClient := &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				rawConn, err := enrollMemListener.Dial()
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(rawConn, &tls.Config{
					RootCAs:    serverCaPool,
					ServerName: "localhost",
					MinVersion: tls.VersionTLS12,
				})
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					_ = rawConn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
		},
		Timeout: 5 * time.Second,
	}

	// 4. Setup In-Memory mTLS 1.3 Server (Strict Mutual TLS)
	clientCaPool := ca.NewCertPoolFromCert(caInstance.Certificate)
	mtlsTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{serverTlsCert},
		ClientCAs:    clientCaPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}

	mtlsMux := http.NewServeMux()
	mtlsMux.Handle("/api/v1/protected/ping", middleware.MtlsAuthMiddleware(deviceRepo)(handlers.NewProtectedPingHandler()))

	mtlsMemListener := newMemListener()
	mtlsListener := tls.NewListener(mtlsMemListener, mtlsTLSConfig)
	mtlsServer := &http.Server{Handler: mtlsMux}
	go func() { _ = mtlsServer.Serve(mtlsListener) }()
	defer func() { _ = mtlsServer.Close() }()

	// 5. Verify plain HTTP to enrollment listener is rejected (fails or returns 400 Bad Request)
	plainClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return enrollMemListener.Dial()
			},
		},
		Timeout: 2 * time.Second,
	}
	plainResp, plainErr := plainClient.Get("http://memory/api/v1/enroll/challenge")
	if plainErr == nil {
		defer plainResp.Body.Close()
		if plainResp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 Bad Request for plain HTTP to HTTPS port, got %d", plainResp.StatusCode)
		}
	}

	// 6. Test GET /api/v1/enroll/challenge over standard TLS (succeeds without client cert)
	resp, err := enrollClient.Get("https://memory/api/v1/enroll/challenge")
	if err != nil {
		t.Fatalf("GET /challenge over TLS failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from /challenge, got %d", resp.StatusCode)
	}

	var challengeResp handlers.ChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&challengeResp); err != nil {
		t.Fatalf("failed to decode challenge response: %v", err)
	}
	if challengeResp.Challenge == "" {
		t.Fatal("expected non-empty challenge")
	}

	// 7. Test unauthenticated request to mTLS port (must fail handshake)

	unauthClient := &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				rawConn, err := mtlsMemListener.Dial()
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(rawConn, &tls.Config{
					RootCAs:    serverCaPool,
					ServerName: "localhost",
				})
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					_ = rawConn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
		},
		Timeout: 3 * time.Second,
	}

	_, err = unauthClient.Get("https://memory/api/v1/protected/ping")
	if err == nil {
		t.Fatal("expected TLS handshake failure for client without certificate, got nil error")
	}

	// 6. Generate valid client key & certificate signed by the CA for device 'dev-e2e-100'.
	// The identity is derived server-side from the public key hash.
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "dev-e2e-100"},
	}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, clientKey)

	identity, err := attestation.PublicKeyFingerprint(&clientKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to derive identity: %v", err)
	}

	clientCert, _, err := caInstance.SignCSR(csrDER, identity, 24*time.Hour)
	if err != nil {
		t.Fatalf("SignCSR failed: %v", err)
	}

	// Register device in repository
	_ = deviceRepo.RegisterDevice(storage.DeviceRecord{
		Identity:              identity,
		Label:                 "dev-e2e-100",
		CertSerial:            clientCert.SerialNumber.String(),
		EnrolledAt:            time.Now(),
		IsRevoked:             false,
		HardwareSecurityLevel: "STRONGBOX",
	})

	clientTlsCert := tls.Certificate{
		Certificate: [][]byte{clientCert.Raw},
		PrivateKey:  clientKey,
	}

	authClient := &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				rawConn, err := mtlsMemListener.Dial()
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(rawConn, &tls.Config{
					RootCAs:      serverCaPool,
					Certificates: []tls.Certificate{clientTlsCert},
					ServerName:   "localhost",
					MinVersion:   tls.VersionTLS13,
				})
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					_ = rawConn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
		},
		Timeout: 5 * time.Second,
	}

	// 7. Test authenticated mTLS request -> must succeed 200 OK
	pingResp, err := authClient.Get("https://memory/api/v1/protected/ping")
	if err != nil {
		t.Fatalf("authenticated mTLS request failed: %v", err)
	}
	defer pingResp.Body.Close()

	if pingResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(pingResp.Body)
		t.Fatalf("expected 200 OK, got %d: %s", pingResp.StatusCode, string(body))
	}

	var res handlers.ProtectedResponse
	if err := json.NewDecoder(pingResp.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode ping response: %v", err)
	}

	if res.Status != "ok" || res.ClientIdentity != identity || res.DeviceLabel != "dev-e2e-100" {
		t.Fatalf("unexpected protected response: %+v", res)
	}

	// 8. Revoke device -> verify mTLS endpoint returns 403 Forbidden
	_ = deviceRepo.RevokeDevice(identity)
	revokedResp, err := authClient.Get("https://memory/api/v1/protected/ping")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer revokedResp.Body.Close()

	if revokedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for revoked device, got %d", revokedResp.StatusCode)
	}
}
