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
}

// LoadConfig creates a configuration initialized with defaults and overridden by environment variables.
func LoadConfig() *Config {
	certDir := getEnv("CERT_DIR", "certs")
	serverCert := getEnv("SERVER_CERT_PATH", filepath.Join(certDir, "server.crt"))
	serverKey := getEnv("SERVER_KEY_PATH", filepath.Join(certDir, "server.key"))

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
		DevMode:        getEnvBool("DEV_MODE", false),
	}
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

func getEnvBool(key string, defaultVal bool) bool {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		if parsed, err := strconv.ParseBool(val); err == nil {
			return parsed
		}
	}
	return defaultVal
}
