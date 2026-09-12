package config

import (
	"testing"
	"time"
)

func TestLoadConfigDefaults(t *testing.T) {
	for _, key := range []string{
		"ENROLL_PORT", "MTLS_PORT", "CERT_DIR", "CA_CERT_PATH", "CA_KEY_PATH",
		"SERVER_CERT_PATH", "SERVER_KEY_PATH", "ENROLL_CERT_PATH", "ENROLL_KEY_PATH",
		"CHALLENGE_TTL_SECONDS", "CLIENT_CERT_TTL_HOURS", "DEV_MODE",
		"EXPECTED_APP_PACKAGE", "MIN_OS_VERSION", "MIN_PATCH_LEVEL",
		"ATTESTATION_REVOCATION_LIST_URL", "REQUIRE_REVOCATION_CHECK",
	} {
		t.Setenv(key, "")
	}

	cfg := LoadConfig()

	if cfg.EnrollPort != ":8080" {
		t.Errorf("expected default enroll port :8080, got %s", cfg.EnrollPort)
	}
	if cfg.MtlsPort != ":8443" {
		t.Errorf("expected default mTLS port :8443, got %s", cfg.MtlsPort)
	}
	if cfg.ChallengeTTL != 60*time.Second {
		t.Errorf("expected default challenge TTL of 60s, got %v", cfg.ChallengeTTL)
	}
	if cfg.ClientCertTTL != 7*24*time.Hour {
		t.Errorf("expected default client cert TTL of 7d, got %v", cfg.ClientCertTTL)
	}
	if cfg.DevMode {
		t.Error("expected dev mode to default to false")
	}
	if cfg.RequireRevocationCheck != true {
		t.Error("expected revocation check to default to true outside dev mode")
	}
	if cfg.ExpectedAppPackage != "com.kypeli.mtlspoc" {
		t.Errorf("expected default expected app package, got %q", cfg.ExpectedAppPackage)
	}
	if cfg.MinOsVersion != 0 || cfg.MinPatchLevel != 0 {
		t.Errorf("expected OS version/patch enforcement to default to 0, got %d/%d", cfg.MinOsVersion, cfg.MinPatchLevel)
	}
}

func TestLoadConfigEnvOverrides(t *testing.T) {
	t.Setenv("ENROLL_PORT", ":9080")
	t.Setenv("MTLS_PORT", ":9443")
	t.Setenv("CHALLENGE_TTL_SECONDS", "300")
	t.Setenv("CLIENT_CERT_TTL_HOURS", "48")
	t.Setenv("DEV_MODE", "true")
	t.Setenv("EXPECTED_APP_PACKAGE", "com.example.other")
	t.Setenv("MIN_OS_VERSION", "140000")
	t.Setenv("MIN_PATCH_LEVEL", "20240101")
	t.Setenv("REQUIRE_REVOCATION_CHECK", "false")
	t.Setenv("ATTESTATION_REVOCATION_LIST_URL", "https://example.com/status")

	cfg := LoadConfig()

	if cfg.EnrollPort != ":9080" || cfg.MtlsPort != ":9443" {
		t.Errorf("unexpected ports: %s / %s", cfg.EnrollPort, cfg.MtlsPort)
	}
	if cfg.ChallengeTTL != 300*time.Second {
		t.Errorf("expected 300s challenge TTL, got %v", cfg.ChallengeTTL)
	}
	if cfg.ClientCertTTL != 48*time.Hour {
		t.Errorf("expected 48h client cert TTL, got %v", cfg.ClientCertTTL)
	}
	if !cfg.DevMode {
		t.Error("expected dev mode to be enabled")
	}
	if cfg.RequireRevocationCheck {
		t.Error("expected revocation check to be disabled by env override")
	}
	if cfg.ExpectedAppPackage != "com.example.other" {
		t.Errorf("unexpected expected app package: %q", cfg.ExpectedAppPackage)
	}
	if cfg.MinOsVersion != 140000 || cfg.MinPatchLevel != 20240101 {
		t.Errorf("unexpected OS version/patch minimums: %d/%d", cfg.MinOsVersion, cfg.MinPatchLevel)
	}
	if cfg.RevocationListURL != "https://example.com/status" {
		t.Errorf("unexpected revocation list URL: %q", cfg.RevocationListURL)
	}
}

func TestLoadConfigDevModeDisablesRevocationByDefault(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("REQUIRE_REVOCATION_CHECK", "")

	cfg := LoadConfig()
	if cfg.RequireRevocationCheck {
		t.Error("expected revocation check to default to false in dev mode")
	}
}
