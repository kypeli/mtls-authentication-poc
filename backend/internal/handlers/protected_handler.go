package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/kypeli/mtls-poc/backend/internal/middleware"
)

// ProtectedResponse represents the response returned by authenticated mTLS endpoints.
type ProtectedResponse struct {
	Status         string `json:"status"`
	Message        string `json:"message"`
	ClientIdentity string `json:"client_identity"`
	DeviceID       string `json:"device_id"`
	CertSerial     string `json:"cert_serial"`
	Timestamp      int64  `json:"timestamp"`
}

// ProtectedPingHandler handles GET /api/v1/protected/ping.
type ProtectedPingHandler struct{}

// NewProtectedPingHandler creates a new ProtectedPingHandler.
func NewProtectedPingHandler() *ProtectedPingHandler {
	return &ProtectedPingHandler{}
}

func (h *ProtectedPingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	identity, ok := middleware.GetDeviceIdentity(r.Context())
	if !ok {
		log.Printf("[PROTECTED-PING] ❌ Unauthorized ping from %s: missing device context", r.RemoteAddr)
		http.Error(w, "Unauthorized: missing device context", http.StatusUnauthorized)
		return
	}

	log.Printf("[PROTECTED-PING] 🏓 Ping from authenticated device %q (Serial=%s, RemoteAddr=%s)",
		identity.DeviceID, identity.CertSerial, r.RemoteAddr)

	resp := ProtectedResponse{
		Status:         "ok",
		Message:        "mTLS handshake verified successfully",
		ClientIdentity: identity.DeviceID,
		DeviceID:       identity.DeviceID,
		CertSerial:     identity.CertSerial,
		Timestamp:      time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
