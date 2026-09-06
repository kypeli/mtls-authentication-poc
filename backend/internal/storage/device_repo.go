package storage

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrDeviceNotFound = errors.New("device not found")
	ErrDeviceRevoked  = errors.New("device is revoked")
)

// DeviceRecord stores metadata about an enrolled hardware device.
type DeviceRecord struct {
	DeviceID              string    `json:"device_id"`
	PublicKeyFingerprint  string    `json:"public_key_fingerprint"`
	CertSerial            string    `json:"cert_serial"`
	EnrolledAt            time.Time `json:"enrolled_at"`
	IsRevoked             bool      `json:"is_revoked"`
	HardwareSecurityLevel string    `json:"hardware_security_level"`
}

// DeviceRepo manages device registration and revocation.
type DeviceRepo interface {
	RegisterDevice(record DeviceRecord) error
	GetDevice(deviceID string) (*DeviceRecord, error)
	RevokeDevice(deviceID string) error
	IsDeviceActive(deviceID string) bool
}

type memoryDeviceRepo struct {
	mu      sync.RWMutex
	devices map[string]DeviceRecord
}

// NewMemoryDeviceRepo constructs an in-memory thread-safe DeviceRepo.
func NewMemoryDeviceRepo() DeviceRepo {
	return &memoryDeviceRepo{
		devices: make(map[string]DeviceRecord),
	}
}

func (r *memoryDeviceRepo) RegisterDevice(record DeviceRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.devices[record.DeviceID] = record
	return nil
}

func (r *memoryDeviceRepo) GetDevice(deviceID string) (*DeviceRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, exists := r.devices[deviceID]
	if !exists {
		return nil, ErrDeviceNotFound
	}
	return &record, nil
}

func (r *memoryDeviceRepo) RevokeDevice(deviceID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, exists := r.devices[deviceID]
	if !exists {
		return ErrDeviceNotFound
	}
	record.IsRevoked = true
	r.devices[deviceID] = record
	return nil
}

func (r *memoryDeviceRepo) IsDeviceActive(deviceID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, exists := r.devices[deviceID]
	if !exists {
		return false
	}
	return !record.IsRevoked
}
