package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

type mockChainConfig struct {
	Challenge         []byte
	SecurityLevel     SecurityLevel
	DeviceLocked      bool
	VerifiedBootState VerifiedBootState
	OmitExtension     bool
}

func generateMockAttestationChain(t *testing.T, cfg mockChainConfig) (*x509.Certificate, *ecdsa.PrivateKey, [][]byte) {
	// 1. Generate Root CA
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to gen root key: %v", err)
	}
	rootTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Mock Google Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create root cert: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	// 2. Generate Intermediate CA
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to gen inter key: %v", err)
	}
	interTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Mock Google Intermediate CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, &interTemplate, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create intermediate cert: %v", err)
	}
	interCert, _ := x509.ParseCertificate(interDER)

	// 3. Generate Device Key & Attestation Extension
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to gen device key: %v", err)
	}

	var extensions []pkix.Extension
	if !cfg.OmitExtension {
		rot := RootOfTrust{
			VerifiedBootKey:   []byte("test-boot-key"),
			DeviceLocked:      cfg.DeviceLocked,
			VerifiedBootState: asn1.Enumerated(cfg.VerifiedBootState),
		}
		rotBytes, err := asn1.Marshal(rot)
		if err != nil {
			t.Fatalf("failed to marshal rot: %v", err)
		}

		rotTagged, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        TagRootOfTrust,
			IsCompound: true,
			Bytes:      rotBytes,
		})
		if err != nil {
			t.Fatalf("failed to marshal tagged rot: %v", err)
		}

		teeEnforcedSeq, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSequence,
			IsCompound: true,
			Bytes:      rotTagged,
		})
		if err != nil {
			t.Fatalf("failed to marshal tee sequence: %v", err)
		}

		var teeRaw asn1.RawValue
		if _, err := asn1.Unmarshal(teeEnforcedSeq, &teeRaw); err != nil {
			t.Fatalf("failed to unmarshal teeRaw: %v", err)
		}

		kd := KeyDescription{
			AttestationVersion:       3,
			AttestationSecurityLevel: asn1.Enumerated(cfg.SecurityLevel),
			KeymasterVersion:         4,
			KeymasterSecurityLevel:   asn1.Enumerated(cfg.SecurityLevel),
			AttestationChallenge:     cfg.Challenge,
			UniqueID:                 []byte("device-unique-id"),
			TeeEnforced:              teeRaw,
		}
		kdBytes, err := asn1.Marshal(kd)
		if err != nil {
			t.Fatalf("failed to marshal kd: %v", err)
		}

		extensions = append(extensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17},
			Value: kdBytes,
		})
	}

	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "Android Keystore Key"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: extensions,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, interCert, &deviceKey.PublicKey, interKey)
	if err != nil {
		t.Fatalf("failed to create leaf cert: %v", err)
	}

	chainDER := [][]byte{leafDER, interDER, rootDER}
	return rootCert, deviceKey, chainDER
}

func TestVerifyAttestationSuccess(t *testing.T) {
	challenge := []byte("secret-challenge-nonce-12345678")
	rootCert, devKey, chainDER := generateMockAttestationChain(t, mockChainConfig{
		Challenge:         challenge,
		SecurityLevel:     SecurityLevelStrongBox,
		DeviceLocked:      true,
		VerifiedBootState: VerifiedBootStateVerified,
	})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	verifier := MustNewVerifier(rootPool, DefaultStrictPolicy())

	record, err := verifier.VerifyAttestation(chainDER, challenge, &devKey.PublicKey)
	if err != nil {
		t.Fatalf("expected successful attestation verification, got error: %v", err)
	}

	if record.AttestationSecurityLevel != SecurityLevelStrongBox {
		t.Errorf("expected STRONGBOX security level, got %s", record.AttestationSecurityLevel)
	}
	if !record.DeviceLocked {
		t.Error("expected device to be locked")
	}
	if record.VerifiedBootState != VerifiedBootStateVerified {
		t.Errorf("expected Verified boot state, got %s", record.VerifiedBootState)
	}
}

func TestVerifyAttestationChallengeMismatch(t *testing.T) {
	challenge := []byte("original-challenge")
	rootCert, devKey, chainDER := generateMockAttestationChain(t, mockChainConfig{
		Challenge:         challenge,
		SecurityLevel:     SecurityLevelTrustedEnvironment,
		DeviceLocked:      true,
		VerifiedBootState: VerifiedBootStateVerified,
	})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	verifier := MustNewVerifier(rootPool, DefaultStrictPolicy())

	_, err := verifier.VerifyAttestation(chainDER, []byte("different-challenge"), &devKey.PublicKey)
	if err == nil {
		t.Fatal("expected error for challenge mismatch, got nil")
	}
}

func TestVerifyAttestationUnlockedBootloaderFailsStrict(t *testing.T) {
	challenge := []byte("challenge-123")
	rootCert, devKey, chainDER := generateMockAttestationChain(t, mockChainConfig{
		Challenge:         challenge,
		SecurityLevel:     SecurityLevelTrustedEnvironment,
		DeviceLocked:      false, // Unlocked
		VerifiedBootState: VerifiedBootStateSelfSigned,
	})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	strictVerifier := MustNewVerifier(rootPool, DefaultStrictPolicy())
	if _, err := strictVerifier.VerifyAttestation(chainDER, challenge, &devKey.PublicKey); err == nil {
		t.Fatal("expected strict policy to reject unlocked bootloader")
	}

	devVerifier := MustNewVerifier(rootPool, DevelopmentPolicy())
	if _, err := devVerifier.VerifyAttestation(chainDER, challenge, &devKey.PublicKey); err != nil {
		t.Fatalf("expected development policy to allow unlocked bootloader, got: %v", err)
	}
}

func TestVerifyAttestationPublicKeyMismatch(t *testing.T) {
	challenge := []byte("challenge-123")
	rootCert, _, chainDER := generateMockAttestationChain(t, mockChainConfig{
		Challenge:         challenge,
		SecurityLevel:     SecurityLevelStrongBox,
		DeviceLocked:      true,
		VerifiedBootState: VerifiedBootStateVerified,
	})

	differentKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	verifier := MustNewVerifier(rootPool, DefaultStrictPolicy())
	_, err := verifier.VerifyAttestation(chainDER, challenge, &differentKey.PublicKey)
	if err == nil {
		t.Fatal("expected error on public key mismatch between CSR and attestation leaf, got nil")
	}
}

func TestVerifyAttestationDevPolicyTolerances(t *testing.T) {
	challenge := []byte("challenge-dev")
	_, devKey, chainDER := generateMockAttestationChain(t, mockChainConfig{
		Challenge:         challenge,
		SecurityLevel:     SecurityLevelSoftware,
		DeviceLocked:      false,
		VerifiedBootState: VerifiedBootStateUnverified,
	})

	// Use an EMPTY root pool to prove SkipChainValidation works in DevelopmentPolicy
	emptyPool := x509.NewCertPool()
	devVerifier := MustNewVerifier(emptyPool, DevelopmentPolicy())

	// 1. With software chain (not in root pool) -> must succeed under DevelopmentPolicy
	rec, err := devVerifier.VerifyAttestation(chainDER, challenge, &devKey.PublicKey)
	if err != nil {
		t.Fatalf("expected DevelopmentPolicy to succeed with software chain, got: %v", err)
	}
	if rec.AttestationSecurityLevel != SecurityLevelSoftware {
		t.Errorf("expected SOFTWARE security level, got: %v", rec.AttestationSecurityLevel)
	}

	// 2. With completely empty chain -> must succeed under DevelopmentPolicy
	emptyRec, err := devVerifier.VerifyAttestation(nil, challenge, &devKey.PublicKey)
	if err != nil {
		t.Fatalf("expected DevelopmentPolicy to succeed with empty chain, got: %v", err)
	}
	if emptyRec.AttestationSecurityLevel != SecurityLevelSoftware {
		t.Errorf("expected SOFTWARE level on empty chain, got: %v", emptyRec.AttestationSecurityLevel)
	}

	// 3. Strict policy must reject empty chain and unknown authority
	strictVerifier := MustNewVerifier(emptyPool, DefaultStrictPolicy())
	if _, err := strictVerifier.VerifyAttestation(nil, challenge, &devKey.PublicKey); err == nil {
		t.Fatal("expected DefaultStrictPolicy to reject empty chain")
	}
	if _, err := strictVerifier.VerifyAttestation(chainDER, challenge, &devKey.PublicKey); err == nil {
		t.Fatal("expected DefaultStrictPolicy to reject chain not in root pool")
	}
}
