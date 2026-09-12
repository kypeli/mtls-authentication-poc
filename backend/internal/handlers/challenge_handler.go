package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/kypeli/mtls-poc/backend/internal/storage"
)

// ChallengeHandler handles challenge generation requests.
type ChallengeHandler struct {
	store storage.ChallengeStore
	ttl   time.Duration
}

// NewChallengeHandler creates a new ChallengeHandler.
func NewChallengeHandler(store storage.ChallengeStore, ttl time.Duration) *ChallengeHandler {
	return &ChallengeHandler{
		store: store,
		ttl:   ttl,
	}
}

// ChallengeResponse represents the JSON response for challenge generation.
type ChallengeResponse struct {
	Challenge string `json:"challenge"`
	ExpiresIn int64  `json:"expires_in"`
	ExpiresAt string `json:"expires_at"`
}

func (h *ChallengeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	challenge, expiresAt, err := h.store.GenerateAndStoreChallenge(h.ttl)
	if err != nil {
		log.Printf("[CHALLENGE] ❌ Failed to generate attestation challenge for %s: %v", r.RemoteAddr, err)
		http.Error(w, "Failed to generate attestation challenge", http.StatusInternalServerError)
		return
	}

	log.Printf("[CHALLENGE] 🎲 Issued challenge for %s: prefix=%s... (TTL: %v, ExpiresAt: %s)",
		r.RemoteAddr, challenge[:min(len(challenge), 12)], h.ttl, expiresAt.UTC().Format(time.RFC3339))

	resp := ChallengeResponse{
		Challenge: challenge,
		ExpiresIn: int64(h.ttl.Seconds()),
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
