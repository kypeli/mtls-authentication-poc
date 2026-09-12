package attestation

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DefaultRevocationListURL is Google's official attestation revocation status list.
const DefaultRevocationListURL = "https://android.googleapis.com/attestation/status"

// PublicKeyFingerprint returns the hex-encoded SHA-256 of the marshaled
// SubjectPublicKeyInfo for the given public key. It is the canonical,
// server-derived identity for enrolled devices and matches the key IDs used
// by Google's attestation revocation status list.
func PublicKeyFingerprint(publicKey crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// RevocationStatusClient fetches and caches Google's attestation revocation
// status list. Entries are keyed by the hex-encoded SHA-256 of the certificate
// public key and carry a status such as "REVOKED".
type RevocationStatusClient struct {
	listURL    string
	httpClient *http.Client
	ttl        time.Duration

	mu      sync.Mutex
	entries map[string]string
	fetched time.Time
}

// statusListResponse models the JSON document published at DefaultRevocationListURL.
type statusListResponse struct {
	Entries map[string]struct {
		Status string `json:"status"`
	} `json:"entries"`
}

// NewRevocationStatusClient constructs a status list client. When listURL is empty
// the official Google endpoint is used; when httpClient is nil a default client is used.
func NewRevocationStatusClient(listURL string, ttl time.Duration, httpClient *http.Client) *RevocationStatusClient {
	if listURL == "" {
		listURL = DefaultRevocationListURL
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &RevocationStatusClient{
		listURL:    listURL,
		httpClient: httpClient,
		ttl:        ttl,
	}
}

// IsKeyRevoked reports whether the given public key appears with status REVOKED
// in the status list, refreshing the cached list when stale. Errors are returned
// (fail closed) so callers can reject enrollment when the list is unavailable.
func (c *RevocationStatusClient) IsKeyRevoked(publicKey crypto.PublicKey) (bool, error) {
	id, err := PublicKeyFingerprint(publicKey)
	if err != nil {
		return false, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.entries == nil || time.Since(c.fetched) > c.ttl {
		if err := c.fetchLocked(); err != nil {
			return false, err
		}
	}

	status, present := c.entries[id]
	return present && strings.EqualFold(status, "REVOKED"), nil
}

func (c *RevocationStatusClient) fetchLocked() error {
	resp, err := c.httpClient.Get(c.listURL)
	if err != nil {
		return fmt.Errorf("failed to fetch attestation revocation status list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("attestation revocation status list returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("failed to read attestation revocation status list: %w", err)
	}

	var parsed statusListResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("failed to parse attestation revocation status list: %w", err)
	}

	entries := make(map[string]string, len(parsed.Entries))
	for id, entry := range parsed.Entries {
		entries[strings.ToLower(id)] = entry.Status
	}
	c.entries = entries
	c.fetched = time.Now()
	return nil
}
