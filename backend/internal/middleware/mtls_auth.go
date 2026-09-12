package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/kypeli/mtls-poc/backend/internal/storage"
)

type contextKey string

const DeviceContextKey contextKey = "device_identity"

// DeviceIdentity represents identity extracted from the verified mTLS client certificate.
type DeviceIdentity struct {
	DeviceID   string
	CertSerial string
	Record     *storage.DeviceRecord
}

// MtlsAuthMiddleware ensures a valid client certificate was presented and verified during TLS handshake.
func MtlsAuthMiddleware(repo storage.DeviceRepo) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				log.Printf("[MTLS-AUTH] ❌ Rejecting %s %s from %s: no client certificate presented in TLS handshake", r.Method, r.URL.Path, r.RemoteAddr)
				http.Error(w, "Mutual TLS authentication required: no client certificate presented", http.StatusUnauthorized)
				return
			}

			clientCert := r.TLS.PeerCertificates[0]
			deviceID := clientCert.Subject.CommonName

			// Fallback to SAN URIs (urn:device:<id>)
			if deviceID == "" {
				for _, u := range clientCert.URIs {
					if strings.HasPrefix(u.String(), "urn:device:") {
						deviceID = strings.TrimPrefix(u.String(), "urn:device:")
						break
					}
				}
			}

			log.Printf("[MTLS-AUTH] 🔍 Client cert presented by %s: CN=%q, Serial=%s, Issuer=%q, URIs=%v",
				r.RemoteAddr, clientCert.Subject.CommonName, clientCert.SerialNumber.String(), clientCert.Issuer.CommonName, clientCert.URIs)

			if deviceID == "" {
				log.Printf("[MTLS-AUTH] ❌ Rejecting client from %s: unable to extract device identity from cert", r.RemoteAddr)
				http.Error(w, "Mutual TLS authentication failed: unable to identify device from client certificate", http.StatusForbidden)
				return
			}

			// Validate against device repository if repo is provided
			var record *storage.DeviceRecord
			if repo != nil {
				if !repo.IsDeviceActive(deviceID) {
					log.Printf("[MTLS-AUTH] ❌ Device %q from %s rejected: unauthorized or revoked in registry", deviceID, r.RemoteAddr)
					http.Error(w, "Device is unauthorized or revoked", http.StatusForbidden)
					return
				}
				record, _ = repo.GetDevice(deviceID)
			}

			log.Printf("[MTLS-AUTH] ✅ Authenticated device %q (Serial=%s) from %s", deviceID, clientCert.SerialNumber.String(), r.RemoteAddr)

			identity := &DeviceIdentity{
				DeviceID:   deviceID,
				CertSerial: clientCert.SerialNumber.String(),
				Record:     record,
			}

			ctx := context.WithValue(r.Context(), DeviceContextKey, identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetDeviceIdentity extracts the DeviceIdentity from the request context.
func GetDeviceIdentity(ctx context.Context) (*DeviceIdentity, bool) {
	identity, ok := ctx.Value(DeviceContextKey).(*DeviceIdentity)
	return identity, ok && identity != nil
}
