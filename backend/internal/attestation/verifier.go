package attestation

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// Verifier verifies Android Key Attestation certificate chains.
type Verifier struct {
	rootPool *x509.CertPool
	policy   Policy
}

// NewVerifier constructs a Verifier with the specified root pool and security policy.
// If rootPool is nil, it initializes the pool with Google's official root certificates
// and fails loudly if any embedded certificate cannot be parsed.
func NewVerifier(rootPool *x509.CertPool, policy Policy) (*Verifier, error) {
	if rootPool == nil {
		var err error
		rootPool, err = NewGoogleRootCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize Google Root CA pool: %w", err)
		}
	}
	return &Verifier{
		rootPool: rootPool,
		policy:   policy,
	}, nil
}

// MustNewVerifier constructs a Verifier or panics if root pool initialization fails.
func MustNewVerifier(rootPool *x509.CertPool, policy Policy) *Verifier {
	v, err := NewVerifier(rootPool, policy)
	if err != nil {
		panic(err)
	}
	return v
}

// Policy returns the verifier's active security policy.
func (v *Verifier) Policy() Policy {
	return v.policy
}

// VerifyAttestation verifies:
// 1. Certificate chain validity up to the trusted root pool (unless skipped in dev mode).
// 2. That the leaf certificate public key matches the CSR public key.
// 3. The Android Key Attestation extension (OID 1.3.6.1.4.1.11129.2.1.17).
// 4. Challenge equality and security policy conformance.
func (v *Verifier) VerifyAttestation(
	chainDER [][]byte,
	expectedChallenge []byte,
	expectedCsrPublicKey crypto.PublicKey,
) (*AttestationRecord, error) {
	if len(chainDER) == 0 {
		if v.policy.AllowEmptyAttestation {
			return &AttestationRecord{
				AttestationSecurityLevel: SecurityLevelSoftware,
				KeymasterSecurityLevel:   SecurityLevelSoftware,
				AttestationChallenge:     expectedChallenge,
			}, nil
		}
		return nil, errors.New("attestation certificate chain is empty")
	}

	if len(chainDER) < 2 && !v.policy.AllowEmptyAttestation {
		return nil, errors.New("attestation certificate chain must contain at least leaf and intermediate certificates")
	}

	certs := make([]*x509.Certificate, len(chainDER))
	for i, der := range chainDER {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate at index %d: %w", i, err)
		}
		certs[i] = c
	}

	leaf := certs[0]

	// 1. Verify certificate chain back to trusted roots (unless skipped in dev mode)
	if !v.policy.SkipChainValidation {
		if len(certs) < 2 {
			return nil, errors.New("attestation certificate chain must contain at least leaf and intermediate certificates")
		}
		intermediates := x509.NewCertPool()
		for i := 1; i < len(certs); i++ {
			intermediates.AddCert(certs[i])
		}

		opts := x509.VerifyOptions{
			Roots:         v.rootPool,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}

		if _, err := leaf.Verify(opts); err != nil {
			return nil, fmt.Errorf("attestation certificate chain verification failed: %w", err)
		}
	}

	// 2. Verify leaf public key matches the public key submitted in CSR
	if expectedCsrPublicKey != nil {
		leafPKIX, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal leaf public key: %w", err)
		}
		csrPKIX, err := x509.MarshalPKIXPublicKey(expectedCsrPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal CSR public key: %w", err)
		}
		if !bytes.Equal(leafPKIX, csrPKIX) {
			return nil, errors.New("CSR public key does not match attestation leaf public key")
		}
	}

	// 3. Locate Key Attestation extension OID 1.3.6.1.4.1.11129.2.1.17
	var attestationBytes []byte
	for _, ext := range leaf.Extensions {
		if ext.Id.String() == AndroidKeyAttestationOID {
			attestationBytes = ext.Value
			break
		}
	}
	if len(attestationBytes) == 0 {
		if v.policy.AllowEmptyAttestation {
			return &AttestationRecord{
				AttestationSecurityLevel: SecurityLevelSoftware,
				KeymasterSecurityLevel:   SecurityLevelSoftware,
				AttestationChallenge:     expectedChallenge,
			}, nil
		}
		return nil, fmt.Errorf("missing Android Key Attestation extension OID %s", AndroidKeyAttestationOID)
	}

	// 4. Parse KeyDescription ASN.1 structure
	var kd KeyDescription
	if _, err := asn1.Unmarshal(attestationBytes, &kd); err != nil {
		return nil, fmt.Errorf("failed to parse KeyDescription ASN.1: %w", err)
	}

	// 5. Verify challenge nonce
	if !bytes.Equal(kd.AttestationChallenge, expectedChallenge) {
		return nil, fmt.Errorf("attestation challenge mismatch: expected %x, got %x", expectedChallenge, kd.AttestationChallenge)
	}

	attestationLevel := SecurityLevel(kd.AttestationSecurityLevel)
	keymasterLevel := SecurityLevel(kd.KeymasterSecurityLevel)

	// 6. Enforce hardware security policy
	if v.policy.RequireHardwareBacked {
		if attestationLevel != SecurityLevelTrustedEnvironment && attestationLevel != SecurityLevelStrongBox {
			return nil, fmt.Errorf("untrusted attestation security level: %s (expected TEE or STRONGBOX)", attestationLevel)
		}
		if keymasterLevel != SecurityLevelTrustedEnvironment && keymasterLevel != SecurityLevelStrongBox {
			return nil, fmt.Errorf("untrusted keymaster security level: %s (expected TEE or STRONGBOX)", keymasterLevel)
		}
	}

	// 7. Extract and verify RootOfTrust (from TEE or Software enforced lists)
	rot, err := findRootOfTrust(kd.TeeEnforced.FullBytes)
	if err != nil || rot == nil {
		rot, _ = findRootOfTrust(kd.SoftwareEnforced.FullBytes)
	}

	record := &AttestationRecord{
		AttestationVersion:       kd.AttestationVersion,
		AttestationSecurityLevel: attestationLevel,
		KeymasterVersion:         kd.KeymasterVersion,
		KeymasterSecurityLevel:   keymasterLevel,
		AttestationChallenge:     kd.AttestationChallenge,
	}

	if rot != nil {
		record.DeviceLocked = rot.DeviceLocked
		record.VerifiedBootState = VerifiedBootState(rot.VerifiedBootState)
		record.VerifiedBootKey = rot.VerifiedBootKey

		if v.policy.RequireDeviceLocked && !rot.DeviceLocked {
			return nil, errors.New("security violation: device is not locked (bootloader unlocked)")
		}

		if v.policy.RequireVerifiedBoot && record.VerifiedBootState != VerifiedBootStateVerified {
			return nil, fmt.Errorf("security violation: verified boot state untrusted: %s", record.VerifiedBootState)
		}
	} else if v.policy.RequireVerifiedBoot || v.policy.RequireDeviceLocked {
		return nil, errors.New("root of trust record missing from attestation extension")
	}

	return record, nil
}

// findRootOfTrust walks the ASN.1 sequence of an AuthorizationList to extract Tag 704.
func findRootOfTrust(rawSeq []byte) (*RootOfTrust, error) {
	if len(rawSeq) == 0 {
		return nil, nil
	}

	var rawItems []asn1.RawValue
	if _, err := asn1.Unmarshal(rawSeq, &rawItems); err != nil {
		return nil, err
	}

	for _, item := range rawItems {
		if item.Tag == TagRootOfTrust {
			var rot RootOfTrust
			if _, err := asn1.Unmarshal(item.Bytes, &rot); err != nil {
				return nil, fmt.Errorf("failed to parse RootOfTrust: %w", err)
			}
			return &rot, nil
		}
	}

	return nil, nil
}
