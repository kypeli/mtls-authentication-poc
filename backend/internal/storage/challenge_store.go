package storage

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// ChallengeStore defines operations for managing ephemeral attestation challenges.
type ChallengeStore interface {
	// GenerateAndStoreChallenge creates a 32-byte cryptographically secure challenge with a given TTL.
	GenerateAndStoreChallenge(ttl time.Duration) (string, time.Time, error)
	// VerifyAndConsumeChallenge validates that the challenge exists and is not expired, then consumes it (single-use).
	VerifyAndConsumeChallenge(challenge string) bool
}

type memoryChallengeStore struct {
	mu         sync.Mutex
	challenges map[string]time.Time
}

// NewMemoryChallengeStore constructs a thread-safe in-memory ChallengeStore.
func NewMemoryChallengeStore() ChallengeStore {
	store := &memoryChallengeStore{
		challenges: make(map[string]time.Time),
	}
	// Start background cleanup routine
	go store.cleanupWorker(30 * time.Second)
	return store
}

func (s *memoryChallengeStore) GenerateAndStoreChallenge(ttl time.Duration) (string, time.Time, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", time.Time{}, err
	}
	challenge := base64.StdEncoding.EncodeToString(bytes)
	expiresAt := time.Now().Add(ttl)

	s.mu.Lock()
	s.challenges[challenge] = expiresAt
	s.mu.Unlock()

	return challenge, expiresAt, nil
}

func (s *memoryChallengeStore) VerifyAndConsumeChallenge(challenge string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	expiresAt, exists := s.challenges[challenge]
	if !exists {
		return false
	}

	// Delete immediately to enforce single-use
	delete(s.challenges, challenge)

	return time.Now().Before(expiresAt)
}

func (s *memoryChallengeStore) cleanupWorker(interval time.Duration) {
	ticker := time.NewTicker(interval)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for ch, exp := range s.challenges {
			if now.After(exp) {
				delete(s.challenges, ch)
			}
		}
		s.mu.Unlock()
	}
}
