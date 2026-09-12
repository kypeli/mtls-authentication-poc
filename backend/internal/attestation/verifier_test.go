package attestation

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type mockChainConfig struct {
	Challenge         []byte
	SecurityLevel     SecurityLevel
	DeviceLocked      bool
	VerifiedBootState VerifiedBootState
	OmitExtension     bool
	PackageName       string
	OsVersion         int
	OsPatch           int
}

// buildAuthorizationList marshals an AuthorizationList containing the root of
// trust plus optional package name, OS version, and patch level tags.
func buildAuthorizationList(t *testing.T, cfg mockChainConfig) asn1.RawValue {
	t.Helper()

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

	items := []asn1.RawValue{{FullBytes: rotTagged}}

	if cfg.PackageName != "" {
		appIDDER, err := asn1.Marshal(attestationApplicationId{
			PackageInfos: []attestationPackageInfo{
				{PackageName: []byte(cfg.PackageName), Version: 1},
			},
		})
		if err != nil {
			t.Fatalf("failed to marshal attestation application id: %v", err)
		}
		// Tag 710 carries an OCTET STRING wrapping the DER structure.
		octetDER, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagOctetString,
			IsCompound: false,
			Bytes:      appIDDER,
		})
		if err != nil {
			t.Fatalf("failed to marshal application id octet string: %v", err)
		}
		appIDTagged, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        TagAttestationApplicationId,
			IsCompound: true,
			Bytes:      octetDER,
		})
		if err != nil {
			t.Fatalf("failed to marshal tagged application id: %v", err)
		}
		items = append(items, asn1.RawValue{FullBytes: appIDTagged})
	}

	if cfg.OsVersion > 0 {
		osVersionDER, err := asn1.Marshal(cfg.OsVersion)
		if err != nil {
			t.Fatalf("failed to marshal os version: %v", err)
		}
		tagged, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        TagOSVersion,
			IsCompound: true,
			Bytes:      osVersionDER,
		})
		if err != nil {
			t.Fatalf("failed to marshal tagged os version: %v", err)
		}
		items = append(items, asn1.RawValue{FullBytes: tagged})
	}

	if cfg.OsPatch > 0 {
		patchDER, err := asn1.Marshal(cfg.OsPatch)
		if err != nil {
			t.Fatalf("failed to marshal os patch: %v", err)
		}
		tagged, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        TagOSPatch,
			IsCompound: true,
			Bytes:      patchDER,
		})
		if err != nil {
			t.Fatalf("failed to marshal tagged os patch: %v", err)
		}
		items = append(items, asn1.RawValue{FullBytes: tagged})
	}

	teeEnforcedSeq, err := asn1.Marshal(items)
	if err != nil {
		t.Fatalf("failed to marshal tee sequence: %v", err)
	}

	var teeRaw asn1.RawValue
	if _, err := asn1.Unmarshal(teeEnforcedSeq, &teeRaw); err != nil {
		t.Fatalf("failed to unmarshal teeRaw: %v", err)
	}
	return teeRaw
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
		teeRaw := buildAuthorizationList(t, cfg)

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

func TestVerifyAttestationApplicationIDBinding(t *testing.T) {
	challenge := []byte("challenge-app-id")
	rootCert, devKey, chainDER := generateMockAttestationChain(t, mockChainConfig{
		Challenge:         challenge,
		SecurityLevel:     SecurityLevelStrongBox,
		DeviceLocked:      true,
		VerifiedBootState: VerifiedBootStateVerified,
		PackageName:       "com.kypeli.mtlspoc",
	})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	policy := DefaultStrictPolicy()
	policy.ExpectedPackageName = "com.kypeli.mtlspoc"

	// Matching package name -> success
	verifier := MustNewVerifier(rootPool, policy)
	if _, err := verifier.VerifyAttestation(chainDER, challenge, &devKey.PublicKey); err != nil {
		t.Fatalf("expected matching package name to pass, got: %v", err)
	}

	// Different expected package -> rejected
	verifierWrong := MustNewVerifier(rootPool, DefaultStrictPolicy())
	verifierWrong.policy.ExpectedPackageName = "com.other.app"
	if _, err := verifierWrong.VerifyAttestation(chainDER, challenge, &devKey.PublicKey); err == nil {
		t.Fatal("expected non-matching package name to be rejected")
	}

	// Chain without application ID when policy requires it -> rejected
	_, _, chainNoAppID := generateMockAttestationChain(t, mockChainConfig{
		Challenge:         challenge,
		SecurityLevel:     SecurityLevelStrongBox,
		DeviceLocked:      true,
		VerifiedBootState: VerifiedBootStateVerified,
	})
	if _, err := verifier.VerifyAttestation(chainNoAppID, challenge, &devKey.PublicKey); err == nil {
		t.Fatal("expected missing application ID to be rejected")
	}
}

func TestVerifyAttestationOSVersionAndPatch(t *testing.T) {
	challenge := []byte("challenge-os-version")
	rootCert, devKey, chainDER := generateMockAttestationChain(t, mockChainConfig{
		Challenge:         challenge,
		SecurityLevel:     SecurityLevelStrongBox,
		DeviceLocked:      true,
		VerifiedBootState: VerifiedBootStateVerified,
		OsVersion:         140000,
		OsPatch:           20240601,
	})

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	policy := DefaultStrictPolicy()
	policy.MinOsVersion = 140000
	policy.MinPatchLevel = 20240101

	verifier := MustNewVerifier(rootPool, policy)
	record, err := verifier.VerifyAttestation(chainDER, challenge, &devKey.PublicKey)
	if err != nil {
		t.Fatalf("expected attested OS version/patch to satisfy policy, got: %v", err)
	}
	if record.OsVersion != 140000 || record.OsPatchLevel != 20240601 {
		t.Fatalf("unexpected OS info in record: %d / %d", record.OsVersion, record.OsPatchLevel)
	}

	// Patch level below minimum -> rejected
	strictPatch := DefaultStrictPolicy()
	strictPatch.MinPatchLevel = 20250101
	strictVerifier := MustNewVerifier(rootPool, strictPatch)
	if _, err := strictVerifier.VerifyAttestation(chainDER, challenge, &devKey.PublicKey); err == nil {
		t.Fatal("expected attested patch level below minimum to be rejected")
	}

	// OS version below minimum -> rejected
	strictOS := DefaultStrictPolicy()
	strictOS.MinOsVersion = 150000
	strictOSVerifier := MustNewVerifier(rootPool, strictOS)
	if _, err := strictOSVerifier.VerifyAttestation(chainDER, challenge, &devKey.PublicKey); err == nil {
		t.Fatal("expected attested OS version below minimum to be rejected")
	}
}

func TestVerifyAttestationRevocationList(t *testing.T) {
	challenge := []byte("challenge-revocation")
	rootCert, devKey, chainDER := generateMockAttestationChain(t, mockChainConfig{
		Challenge:         challenge,
		SecurityLevel:     SecurityLevelStrongBox,
		DeviceLocked:      true,
		VerifiedBootState: VerifiedBootStateVerified,
	})

	// Mock status list server revoking the device key
	revokedID, err := PublicKeyFingerprint(&devKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to derive key id: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"entries": map[string]any{
				revokedID: map[string]any{"status": "REVOKED"},
			},
		})
	}))
	defer srv.Close()

	rootPool := x509.NewCertPool()
	rootPool.AddCert(rootCert)

	verifier := MustNewVerifier(rootPool, DefaultStrictPolicy())
	verifier.WithRevocationChecker(NewRevocationStatusClient(srv.URL, time.Minute, srv.Client()))

	if _, err := verifier.VerifyAttestation(chainDER, challenge, &devKey.PublicKey); err == nil {
		t.Fatal("expected revoked attestation key to be rejected")
	}

	// Non-revoked key passes
	rootCert2, devKey2, chainDER2 := generateMockAttestationChain(t, mockChainConfig{
		Challenge:         challenge,
		SecurityLevel:     SecurityLevelStrongBox,
		DeviceLocked:      true,
		VerifiedBootState: VerifiedBootStateVerified,
	})
	rootPool2 := x509.NewCertPool()
	rootPool2.AddCert(rootCert2)
	verifier2 := MustNewVerifier(rootPool2, DefaultStrictPolicy())
	verifier2.WithRevocationChecker(NewRevocationStatusClient(srv.URL, time.Minute, srv.Client()))
	if _, err := verifier2.VerifyAttestation(chainDER2, challenge, &devKey2.PublicKey); err != nil {
		t.Fatalf("expected non-revoked key to pass, got: %v", err)
	}

	// Unreachable status list fails closed when the policy requires the check
	verifier3 := MustNewVerifier(rootPool2, DefaultStrictPolicy())
	verifier3.WithRevocationChecker(NewRevocationStatusClient("http://127.0.0.1:1/status", time.Minute, nil))
	if _, err := verifier3.VerifyAttestation(chainDER2, challenge, &devKey2.PublicKey); err == nil {
		t.Fatal("expected failed revocation fetch to fail closed")
	}
}

func TestExtractChallenge(t *testing.T) {
	challenge := []byte("challenge-extract")
	_, _, chainDER := generateMockAttestationChain(t, mockChainConfig{
		Challenge:         challenge,
		SecurityLevel:     SecurityLevelStrongBox,
		DeviceLocked:      true,
		VerifiedBootState: VerifiedBootStateVerified,
	})

	extracted, err := ExtractChallenge(chainDER)
	if err != nil {
		t.Fatalf("expected challenge extraction to succeed, got: %v", err)
	}
	if !bytes.Equal(extracted, challenge) {
		t.Fatalf("extracted challenge mismatch: %x != %x", extracted, challenge)
	}

	if _, err := ExtractChallenge(nil); err == nil {
		t.Fatal("expected empty chain extraction to fail")
	}
}

// capturedRealDeviceExtension is a genuine KeyMint attestation extension captured
// from a physical device (Android 17, KeyMint 400). It carries the attestation
// application ID under tag 709 with package "com.kypeli.mtlspoc".
const capturedRealDeviceExtension = `MIIBVwICAZAKAQECAgGQCgEBBCAAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHwQAMHm/hT0IAgYBoJWWqR6/hUVDBEEwPzEZMBcEEmNvbS5reXBlbGkubXRsc3BvYwIBATEiBCDbzs69BvxVr7EztqUFsPIrjv2Ei1s8W6a8vlBKhcz71r+FVCIEIOAv9FT+qu1ejBoxFH7SIx3fKBkGhRruHlzc+jieWgIPMIGnoQgxBgIBAgIBA6IDAgEDowQCAgEApQgxBgIBAAIBBKoDAgEBv4N3AgUAv4U+AwIBAL+FQEwwSgQgmsQXQVPUXkVFsPSeIv5jJzmZtqwctpScOp8D7IgH7ukBAf8KAQAEIM1F4XD7cNlzq6gmIkWuF5T6VZe1CGxgDGjEHs7DhxIRv4VBBQIDApgQv4VCBQIDAxdvv4VOBgIEATUnYb+FTwYCBAE1J2E=`

// TestVerifyAttestationRealDeviceExtension runs the full verification pipeline
// against genuine device attestation data (regression for the tag 709 fix).
func TestVerifyAttestationRealDeviceExtension(t *testing.T) {
	kdBytes, err := base64.StdEncoding.DecodeString(capturedRealDeviceExtension)
	if err != nil {
		t.Fatalf("failed to decode captured extension: %v", err)
	}

	// Challenge embedded in the captured extension
	challenge := make([]byte, 32)
	for i := range challenge {
		challenge[i] = byte(i)
	}

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to gen root key: %v", err)
	}
	rootTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create root cert: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	devKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to gen device key: %v", err)
	}
	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Key"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}, Value: kdBytes},
		},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, rootCert, &devKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create leaf cert: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(rootCert)

	policy := DefaultStrictPolicy()
	policy.ExpectedPackageName = "com.kypeli.mtlspoc"
	verifier := MustNewVerifier(pool, policy)

	record, err := verifier.VerifyAttestation([][]byte{leafDER, rootDER}, challenge, &devKey.PublicKey)
	if err != nil {
		t.Fatalf("expected genuine device attestation to verify, got: %v", err)
	}
	if record.AttestationSecurityLevel != SecurityLevelTrustedEnvironment {
		t.Errorf("expected TEE security level, got %s", record.AttestationSecurityLevel)
	}
	if !record.DeviceLocked {
		t.Error("expected device to be locked")
	}
	if record.VerifiedBootState != VerifiedBootStateVerified {
		t.Errorf("expected Verified boot state, got %s", record.VerifiedBootState)
	}
	if record.OsVersion == 0 || record.OsPatchLevel == 0 {
		t.Errorf("expected OS version/patch to be extracted, got %d / %d", record.OsVersion, record.OsPatchLevel)
	}

	// A different expected package must be rejected against the real extension
	verifierWrong := MustNewVerifier(pool, DefaultStrictPolicy())
	verifierWrong.policy.ExpectedPackageName = "com.other.app"
	if _, err := verifierWrong.VerifyAttestation([][]byte{leafDER, rootDER}, challenge, &devKey.PublicKey); err == nil {
		t.Fatal("expected non-matching package to be rejected against real extension")
	}
}
