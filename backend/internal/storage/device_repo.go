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
	// Identity is the server-derived device identity: the hex-encoded SHA-256
	// of the attested public key's SubjectPublicKeyInfo. It is the primary key
	// for the record and can never be chosen by the client.
	Identity string `json:"identity"`
	// Label is the client-supplied device_id, treated as a display label only.
	Label                 string    `json:"label,omitempty"`
	CertSerial            string    `json:"cert_serial"`
	EnrolledAt            time.Time `json:"enrolled_at"`
	IsRevoked             bool      `json:"is_revoked"`
	HardwareSecurityLevel string    `json:"hardware_security_level"`
}

// DeviceRepo manages device registration and revocation.
type DeviceRepo interface {
	RegisterDevice(record DeviceRecord) error
	GetDevice(identity string) (*DeviceRecord, error)
	RevokeDevice(identity string) error
	// RevokeSerial marks a single certificate serial as revoked. Revoked serials
	// are consulted during peer verification so a re-issued or rotated
	// certificate cannot resurrect a revoked device's credentials.
	RevokeSerial(serial string) error
	IsSerialRevoked(serial string) bool
	IsDeviceActive(identity string) bool
}

type memoryDeviceRepo struct {
	mu             sync.RWMutex
	devices        map[string]DeviceRecord
	revokedSerials map[string]struct{}
}

// NewMemoryDeviceRepo constructs an in-memory thread-safe DeviceRepo.
func NewMemoryDeviceRepo() DeviceRepo {
	return &memoryDeviceRepo{
		devices:        make(map[string]DeviceRecord),
		revokedSerials: make(map[string]struct{}),
	}
}

func (r *memoryDeviceRepo) RegisterDevice(record DeviceRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.devices[record.Identity] = record
	return nil
}

func (r *memoryDeviceRepo) GetDevice(identity string) (*DeviceRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, exists := r.devices[identity]
	if !exists {
		return nil, ErrDeviceNotFound
	}
	return &record, nil
}

func (r *memoryDeviceRepo) RevokeDevice(identity string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, exists := r.devices[identity]
	if !exists {
		return ErrDeviceNotFound
	}
	record.IsRevoked = true
	r.devices[identity] = record
	r.revokedSerials[record.CertSerial] = struct{}{}
	return nil
}

func (r *memoryDeviceRepo) RevokeSerial(serial string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revokedSerials[serial] = struct{}{}
	return nil
}

func (r *memoryDeviceRepo) IsSerialRevoked(serial string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, revoked := r.revokedSerials[serial]
	return revoked
}

func (r *memoryDeviceRepo) IsDeviceActive(identity string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	record, exists := r.devices[identity]
	if !exists {
		return false
	}
	return !record.IsRevoked
}
