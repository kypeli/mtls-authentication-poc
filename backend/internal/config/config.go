package config

import (
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Config holds runtime configuration for the mTLS backend service.
type Config struct {
	EnrollPort     string
	MtlsPort       string
	CertDir        string
	CaCertPath     string
	CaKeyPath      string
	ServerCertPath string
	ServerKeyPath  string
	EnrollCertPath string
	EnrollKeyPath  string
	ChallengeTTL   time.Duration
	ClientCertTTL  time.Duration
	DevMode        bool

	// Attestation policy extensions:
	// ExpectedAppPackage, when non-empty, requires the attestation application
	// ID to list this package (binds keys to the app rather than any app).
	ExpectedAppPackage string
	// MinOsVersion / MinPatchLevel, when > 0, enforce the attested OS version
	// (MMmmnn, e.g. 140000) and patch level (YYYYMMDD) tags.
	MinOsVersion  int
	MinPatchLevel int
	// RevocationListURL is the attestation revocation status list endpoint.
	RevocationListURL string
	// RequireRevocationCheck enables consulting the revocation status list
	// (fail closed). Defaults to true unless DevMode.
	RequireRevocationCheck bool
}

// LoadConfig creates a configuration initialized with defaults and overridden by environment variables.
func LoadConfig() *Config {
	certDir := getEnv("CERT_DIR", "certs")
	serverCert := getEnv("SERVER_CERT_PATH", filepath.Join(certDir, "server.crt"))
	serverKey := getEnv("SERVER_KEY_PATH", filepath.Join(certDir, "server.key"))

	devMode := getEnvBool("DEV_MODE", false)

	return &Config{
		EnrollPort:     getEnv("ENROLL_PORT", ":8080"),
		MtlsPort:       getEnv("MTLS_PORT", ":8443"),
		CertDir:        certDir,
		CaCertPath:     getEnv("CA_CERT_PATH", filepath.Join(certDir, "ca.crt")),
		CaKeyPath:      getEnv("CA_KEY_PATH", filepath.Join(certDir, "ca.key")),
		ServerCertPath: serverCert,
		ServerKeyPath:  serverKey,
		EnrollCertPath: getEnv("ENROLL_CERT_PATH", serverCert),
		EnrollKeyPath:  getEnv("ENROLL_KEY_PATH", serverKey),
		ChallengeTTL:   getEnvDuration("CHALLENGE_TTL_SECONDS", 60) * time.Second,
		ClientCertTTL:  getEnvDuration("CLIENT_CERT_TTL_HOURS", 7*24) * time.Hour,
		DevMode:        devMode,

		ExpectedAppPackage:     getEnv("EXPECTED_APP_PACKAGE", "com.kypeli.mtlspoc"),
		MinOsVersion:           getEnvInt("MIN_OS_VERSION", 0),
		MinPatchLevel:          getEnvInt("MIN_PATCH_LEVEL", 0),
		RevocationListURL:      getEnv("ATTESTATION_REVOCATION_LIST_URL", attestationRevocationListURL()),
		RequireRevocationCheck: getEnvBool("REQUIRE_REVOCATION_CHECK", !devMode),
	}
}

func attestationRevocationListURL() string {
	return "https://android.googleapis.com/attestation/status"
}

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return defaultVal
}

func getEnvDuration(key string, defaultVal int) time.Duration {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			return time.Duration(parsed)
		}
	}
	return time.Duration(defaultVal)
}

func getEnvInt(key string, defaultVal int) int {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			return parsed
		}
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		if parsed, err := strconv.ParseBool(val); err == nil {
			return parsed
		}
	}
	return defaultVal
}
