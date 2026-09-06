package attestation

import "encoding/asn1"

const (
	// AndroidKeyAttestationOID is the X.509 extension OID for Key Description.
	AndroidKeyAttestationOID = "1.3.6.1.4.1.11129.2.1.17"

	TagRootOfTrust = 704
	TagOSVersion   = 705
	TagOSPatch     = 706
)

type SecurityLevel int

const (
	SecurityLevelSoftware           SecurityLevel = 0
	SecurityLevelTrustedEnvironment SecurityLevel = 1
	SecurityLevelStrongBox          SecurityLevel = 2
)

func (s SecurityLevel) String() string {
	switch s {
	case SecurityLevelSoftware:
		return "SOFTWARE"
	case SecurityLevelTrustedEnvironment:
		return "TEE"
	case SecurityLevelStrongBox:
		return "STRONGBOX"
	default:
		return "UNKNOWN"
	}
}

type VerifiedBootState int

const (
	VerifiedBootStateVerified   VerifiedBootState = 0
	VerifiedBootStateSelfSigned VerifiedBootState = 1
	VerifiedBootStateUnverified VerifiedBootState = 2
	VerifiedBootStateFailed     VerifiedBootState = 3
)

func (v VerifiedBootState) String() string {
	switch v {
	case VerifiedBootStateVerified:
		return "Verified"
	case VerifiedBootStateSelfSigned:
		return "SelfSigned"
	case VerifiedBootStateUnverified:
		return "Unverified"
	case VerifiedBootStateFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}

// KeyDescription represents the root ASN.1 structure of the Android Key Attestation extension.
type KeyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeymasterVersion         int
	KeymasterSecurityLevel   asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	TeeEnforced              asn1.RawValue
}

// RootOfTrust represents the root of trust record extracted from AuthorizationList (Tag 704).
type RootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState asn1.Enumerated
	VerifiedBootHash  []byte `asn1:"optional"`
}

// AttestationRecord holds parsed, validated metadata about the Android device key.
type AttestationRecord struct {
	AttestationVersion       int
	AttestationSecurityLevel SecurityLevel
	KeymasterVersion         int
	KeymasterSecurityLevel   SecurityLevel
	AttestationChallenge     []byte
	DeviceLocked             bool
	VerifiedBootState        VerifiedBootState
	VerifiedBootKey          []byte
}

// Policy defines requirements for attestation verification.
type Policy struct {
	RequireHardwareBacked bool // Requires TEE or StrongBox
	RequireDeviceLocked   bool // Requires deviceLocked == true
	RequireVerifiedBoot   bool // Requires verifiedBootState == Verified (0)
	SkipChainValidation   bool // In dev mode, skips verifying the cert chain against Google's hardware root
	AllowEmptyAttestation bool // In dev mode, allows enrollment without attestation cert chain
}

// DefaultStrictPolicy returns the production zero-trust security policy.
func DefaultStrictPolicy() Policy {
	return Policy{
		RequireHardwareBacked: true,
		RequireDeviceLocked:   true,
		RequireVerifiedBoot:   true,
		SkipChainValidation:   false,
		AllowEmptyAttestation: false,
	}
}

// DevelopmentPolicy returns a lenient policy for local emulators and development.
func DevelopmentPolicy() Policy {
	return Policy{
		RequireHardwareBacked: false,
		RequireDeviceLocked:   false,
		RequireVerifiedBoot:   false,
		SkipChainValidation:   true,
		AllowEmptyAttestation: true,
	}
}
