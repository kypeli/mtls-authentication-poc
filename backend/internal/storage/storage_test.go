package storage

import (
	"testing"
	"time"
)

func TestChallengeStoreSingleUseAndTTL(t *testing.T) {
	store := NewMemoryChallengeStore()

	ch, _, err := store.GenerateAndStoreChallenge(50 * time.Millisecond)
	if err != nil {
		t.Fatalf("failed to generate challenge: %v", err)
	}

	// First verify should succeed
	if !store.VerifyAndConsumeChallenge(ch) {
		t.Fatal("expected challenge to be valid on first verification")
	}

	// Second verify should fail (single-use)
	if store.VerifyAndConsumeChallenge(ch) {
		t.Fatal("expected challenge to be consumed and fail on second verification")
	}

	// Test expiration
	chExpired, _, err := store.GenerateAndStoreChallenge(10 * time.Millisecond)
	if err != nil {
		t.Fatalf("failed to generate challenge: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	if store.VerifyAndConsumeChallenge(chExpired) {
		t.Fatal("expected expired challenge to fail verification")
	}
}

func TestDeviceRepoRegistrationAndRevocation(t *testing.T) {
	repo := NewMemoryDeviceRepo()

	record := DeviceRecord{
		DeviceID:              "dev-001",
		PublicKeyFingerprint:  "sha256:abcd",
		CertSerial:            "12345",
		EnrolledAt:            time.Now(),
		IsRevoked:             false,
		HardwareSecurityLevel: "STRONGBOX",
	}

	if err := repo.RegisterDevice(record); err != nil {
		t.Fatalf("failed to register device: %v", err)
	}

	if !repo.IsDeviceActive("dev-001") {
		t.Fatal("expected device to be active")
	}

	got, err := repo.GetDevice("dev-001")
	if err != nil {
		t.Fatalf("GetDevice failed: %v", err)
	}
	if got.DeviceID != "dev-001" || got.HardwareSecurityLevel != "STRONGBOX" {
		t.Fatalf("unexpected device record: %+v", got)
	}

	if err := repo.RevokeDevice("dev-001"); err != nil {
		t.Fatalf("RevokeDevice failed: %v", err)
	}

	if repo.IsDeviceActive("dev-001") {
		t.Fatal("expected device to be inactive after revocation")
	}
}
