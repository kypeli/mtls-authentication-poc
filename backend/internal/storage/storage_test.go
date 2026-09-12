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
		Identity:              "aabbccdd00112233",
		Label:                 "dev-001",
		CertSerial:            "12345",
		EnrolledAt:            time.Now(),
		IsRevoked:             false,
		HardwareSecurityLevel: "STRONGBOX",
	}

	if err := repo.RegisterDevice(record); err != nil {
		t.Fatalf("failed to register device: %v", err)
	}

	if !repo.IsDeviceActive(record.Identity) {
		t.Fatal("expected device to be active")
	}

	got, err := repo.GetDevice(record.Identity)
	if err != nil {
		t.Fatalf("GetDevice failed: %v", err)
	}
	if got.Identity != record.Identity || got.HardwareSecurityLevel != "STRONGBOX" {
		t.Fatalf("unexpected device record: %+v", got)
	}

	if repo.IsSerialRevoked("12345") {
		t.Fatal("serial should not be revoked before device revocation")
	}

	if err := repo.RevokeDevice(record.Identity); err != nil {
		t.Fatalf("RevokeDevice failed: %v", err)
	}

	if repo.IsDeviceActive(record.Identity) {
		t.Fatal("expected device to be inactive after revocation")
	}
	if !repo.IsSerialRevoked("12345") {
		t.Fatal("expected certificate serial to be revoked with the device")
	}

	if err := repo.RevokeSerial("99999"); err != nil {
		t.Fatalf("RevokeSerial failed: %v", err)
	}
	if !repo.IsSerialRevoked("99999") {
		t.Fatal("expected revoked serial to be reported")
	}
	if repo.IsSerialRevoked("00000") {
		t.Fatal("unknown serial should not be revoked")
	}
}
