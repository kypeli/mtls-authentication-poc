package attestation

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// maxChainCertificates caps the number of attestation certificates accepted
// in a single enrollment to bound parsing and validation work.
const maxChainCertificates = 16

// Verifier verifies Android Key Attestation certificate chains.
type Verifier struct {
	rootPool    *x509.CertPool
	policy      Policy
	revocations *RevocationStatusClient
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

// WithRevocationChecker attaches a revocation status list client consulted during
// verification when the policy enables CheckRevocationList.
func (v *Verifier) WithRevocationChecker(rc *RevocationStatusClient) *Verifier {
	v.revocations = rc
	return v
}

// Policy returns the verifier's active security policy.
func (v *Verifier) Policy() Policy {
	return v.policy
}

// ExtractChallenge extracts the attestation challenge nonce from the leaf
// certificate's Android Key Attestation extension (OID 1.3.6.1.4.1.11129.2.1.17).
// The challenge is bound to the attested key inside the extension, so it must
// always be read from the chain rather than trusted from the request body.
func ExtractChallenge(chainDER [][]byte) ([]byte, error) {
	if len(chainDER) == 0 {
		return nil, errors.New("attestation certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(chainDER[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}
	for _, ext := range leaf.Extensions {
		if ext.Id.String() == AndroidKeyAttestationOID {
			var kd KeyDescription
			if _, err := asn1.Unmarshal(ext.Value, &kd); err != nil {
				return nil, fmt.Errorf("failed to parse KeyDescription: %w", err)
			}
			return kd.AttestationChallenge, nil
		}
	}
	return nil, errors.New("attestation extension not found in leaf certificate")
}

// VerifyAttestation verifies:
// 1. Certificate chain validity up to the trusted root pool (unless skipped in dev mode).
// 2. That the leaf certificate public key matches the CSR public key.
// 3. The Android Key Attestation extension (OID 1.3.6.1.4.1.11129.2.1.17).
// 4. Challenge equality and security policy conformance.
// 5. Attestation application ID, OS version, patch level, and revocation status.
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

	// Single chain-length check: a leaf plus intermediates are required so the
	// chain can be validated up to the trusted root pool.
	if len(chainDER) < 2 && !v.policy.AllowEmptyAttestation {
		return nil, errors.New("attestation certificate chain must contain at least leaf and intermediate certificates")
	}

	if len(chainDER) > maxChainCertificates {
		return nil, fmt.Errorf("attestation certificate chain exceeds maximum of %d certificates", maxChainCertificates)
	}

	certs := make([]*x509.Certificate, len(chainDER))
	for i, der := range chainDER {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate at index %d: %w", i, err)
		}
		certs[i] = c
	}

	// 0. Consult Google's attestation revocation status list for every chain key
	if v.policy.CheckRevocationList && v.revocations != nil {
		for i, cert := range certs {
			revoked, err := v.revocations.IsKeyRevoked(cert.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("attestation revocation check failed (certificate %d): %w", i, err)
			}
			if revoked {
				return nil, fmt.Errorf("attestation certificate %d is revoked per Google's attestation status list", i)
			}
		}
	}

	leaf := certs[0]

	// 1. Verify certificate chain back to trusted roots (unless skipped in dev mode)
	if !v.policy.SkipChainValidation {
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
		return nil, errors.New("attestation challenge mismatch")
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

	// 7. Extract and verify RootOfTrust. When hardware backing is required, the
	// root of trust must come from the TEE-enforced list; the software-enforced
	// list is attacker-controlled for hardware-attested keys.
	rot, err := findRootOfTrust(kd.TeeEnforced.FullBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TEE-enforced root of trust: %w", err)
	}
	if rot == nil && !v.policy.RequireHardwareBacked {
		rot, err = findRootOfTrust(kd.SoftwareEnforced.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse software-enforced root of trust: %w", err)
		}
	}

	// 8. Enforce attestation application ID binding (tag 709)
	if v.policy.ExpectedPackageName != "" {
		if err := v.verifyApplicationID(&kd, v.policy.ExpectedPackageName); err != nil {
			return nil, err
		}
	}

	// 9. Extract and enforce OS version / patch level tags (705, 706)
	osVersion, osPatch, err := extractOSInfo(&kd, v.policy)
	if err != nil {
		return nil, err
	}

	record := &AttestationRecord{
		AttestationVersion:       kd.AttestationVersion,
		AttestationSecurityLevel: attestationLevel,
		KeymasterVersion:         kd.KeymasterVersion,
		KeymasterSecurityLevel:   keymasterLevel,
		AttestationChallenge:     kd.AttestationChallenge,
		OsVersion:                osVersion,
		OsPatchLevel:             osPatch,
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

// verifyApplicationID ensures the attestation application ID (tag 709) lists
// the expected package name, binding the attested key to this app only.
func (v *Verifier) verifyApplicationID(kd *KeyDescription, expectedPackage string) error {
	appIDRaw, found, err := findTagged(kd.TeeEnforced.FullBytes, TagAttestationApplicationId)
	if err != nil {
		return fmt.Errorf("failed to parse attestation application ID: %w", err)
	}
	if !found {
		appIDRaw, found, err = findTagged(kd.SoftwareEnforced.FullBytes, TagAttestationApplicationId)
		if err != nil {
			return fmt.Errorf("failed to parse attestation application ID: %w", err)
		}
	}
	if !found {
		return fmt.Errorf("attestation application ID missing; expected package %q", expectedPackage)
	}

	packages, err := parseAttestationApplicationId(appIDRaw.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse attestation application ID: %w", err)
	}
	for _, pkg := range packages {
		if string(pkg.PackageName) == expectedPackage {
			return nil
		}
	}
	return fmt.Errorf("attestation application ID does not include expected package %q", expectedPackage)
}

// attestationApplicationId models the DER structure embedded in tag 709:
//
//	AttestationApplicationId ::= SEQUENCE {
//	    packageInfos SET OF AttestationPackageInfo,
//	    signatureDigests SET OF OCTET STRING }
type attestationApplicationId struct {
	PackageInfos []attestationPackageInfo `asn1:"set"`
}

type attestationPackageInfo struct {
	PackageName []byte
	Version     int
}

// parseAttestationApplicationId parses the OCTET STRING value of tag 709 whose
// content is the DER-encoded AttestationApplicationId structure.
func parseAttestationApplicationId(raw []byte) ([]attestationPackageInfo, error) {
	var octet asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &octet); err != nil {
		return nil, err
	}
	var appID attestationApplicationId
	if _, err := asn1.Unmarshal(octet.Bytes, &appID); err != nil {
		return nil, err
	}
	return appID.PackageInfos, nil
}

// extractOSInfo extracts the OS version (tag 705) and OS patch level (tag 706)
// integers and enforces the policy minimums when configured.
func extractOSInfo(kd *KeyDescription, policy Policy) (osVersion int, osPatch int, err error) {
	osVersion, err = findIntTag(kd.TeeEnforced.FullBytes, TagOSVersion)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse OS version tag: %w", err)
	}
	if osVersion == 0 && !policy.RequireHardwareBacked {
		if v, err2 := findIntTag(kd.SoftwareEnforced.FullBytes, TagOSVersion); err2 == nil {
			osVersion = v
		}
	}

	osPatch, err = findIntTag(kd.TeeEnforced.FullBytes, TagOSPatch)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse OS patch level tag: %w", err)
	}
	if osPatch == 0 && !policy.RequireHardwareBacked {
		if v, err2 := findIntTag(kd.SoftwareEnforced.FullBytes, TagOSPatch); err2 == nil {
			osPatch = v
		}
	}

	if minOS := policy.MinOsVersion; minOS > 0 {
		if osVersion == 0 {
			return 0, 0, errors.New("OS version tag missing from attestation but required by policy")
		}
		if osVersion < minOS {
			return 0, 0, fmt.Errorf("attested OS version %d below policy minimum %d", osVersion, minOS)
		}
	}
	if minPatch := policy.MinPatchLevel; minPatch > 0 {
		if osPatch == 0 {
			return 0, 0, errors.New("OS patch level tag missing from attestation but required by policy")
		}
		if osPatch < minPatch {
			return 0, 0, fmt.Errorf("attested OS patch level %d below policy minimum %d", osPatch, minPatch)
		}
	}

	return osVersion, osPatch, nil
}

// findRootOfTrust walks the ASN.1 sequence of an AuthorizationList to extract Tag 704.
func findRootOfTrust(rawSeq []byte) (*RootOfTrust, error) {
	raw, found, err := findTagged(rawSeq, TagRootOfTrust)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	var rot RootOfTrust
	if _, err := asn1.Unmarshal(raw.Bytes, &rot); err != nil {
		return nil, fmt.Errorf("failed to parse RootOfTrust: %w", err)
	}
	return &rot, nil
}

// findTagged returns the first raw element with the given tag in an
// AuthorizationList (a SEQUENCE of context-specific tagged values).
func findTagged(rawSeq []byte, tag int) (asn1.RawValue, bool, error) {
	if len(rawSeq) == 0 {
		return asn1.RawValue{}, false, nil
	}

	var rawItems []asn1.RawValue
	if _, err := asn1.Unmarshal(rawSeq, &rawItems); err != nil {
		return asn1.RawValue{}, false, err
	}

	for _, item := range rawItems {
		if item.Tag == tag {
			return item, true, nil
		}
	}

	return asn1.RawValue{}, false, nil
}

// findIntTag extracts an INTEGER-valued authorization tag (e.g. OS version,
// patch level). Returns 0 when the tag is absent.
func findIntTag(rawSeq []byte, tag int) (int, error) {
	raw, found, err := findTagged(rawSeq, tag)
	if err != nil || !found {
		return 0, err
	}
	var value int
	if _, err := asn1.Unmarshal(raw.Bytes, &value); err != nil {
		return 0, err
	}
	return value, nil
}
