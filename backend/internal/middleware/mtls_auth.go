package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/kypeli/mtls-poc/backend/internal/attestation"
	"github.com/kypeli/mtls-poc/backend/internal/storage"
)

type contextKey string

const DeviceContextKey contextKey = "device_identity"

// DeviceIdentity represents identity extracted from the verified mTLS client certificate.
type DeviceIdentity struct {
	// Identity is the server-derived device identity (certificate CN), bound to
	// the attested public key hash at enrollment time.
	Identity string
	// Label is the client-supplied device_id, display only.
	Label      string
	CertSerial string
	Record     *storage.DeviceRecord
}

// MtlsAuthMiddleware ensures a valid client certificate was presented and verified during TLS handshake.
// Beyond the TLS handshake itself it binds the presented certificate to the device
// registry: the identity (derived from the attested public key hash at enrollment)
// must match the certificate's key fingerprint and CN, the certificate must be the
// currently issued serial for that identity, and neither the identity nor the serial
// may be revoked.
func MtlsAuthMiddleware(repo storage.DeviceRepo) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				log.Printf("[MTLS-AUTH] ❌ Rejecting %s %s from %s: no client certificate presented in TLS handshake", r.Method, r.URL.Path, r.RemoteAddr)
				http.Error(w, "Mutual TLS authentication required: no client certificate presented", http.StatusUnauthorized)
				return
			}

			clientCert := r.TLS.PeerCertificates[0]
			identity := clientCert.Subject.CommonName

			// Fallback to SAN URIs (urn:device:<id>)
			if identity == "" {
				for _, u := range clientCert.URIs {
					if strings.HasPrefix(u.String(), "urn:device:") {
						identity = strings.TrimPrefix(u.String(), "urn:device:")
						break
					}
				}
			}

			log.Printf("[MTLS-AUTH] 🔍 Client cert presented by %s: CN=%q, Serial=%s, Issuer=%q, URIs=%v",
				r.RemoteAddr, clientCert.Subject.CommonName, clientCert.SerialNumber.String(), clientCert.Issuer.CommonName, clientCert.URIs)

			if identity == "" {
				log.Printf("[MTLS-AUTH] ❌ Rejecting client from %s: unable to extract device identity from cert", r.RemoteAddr)
				http.Error(w, "Mutual TLS authentication failed: unable to identify device from client certificate", http.StatusForbidden)
				return
			}

			// Key binding: the presented certificate's public key fingerprint must
			// equal the claimed identity, which was derived server-side from the
			// attested key at enrollment.
			fingerprint, err := attestation.PublicKeyFingerprint(clientCert.PublicKey)
			if err != nil || fingerprint != identity {
				log.Printf("[MTLS-AUTH] ❌ Client %q from %s rejected: certificate key does not match claimed identity", identity, r.RemoteAddr)
				http.Error(w, "Mutual TLS authentication failed: certificate identity mismatch", http.StatusForbidden)
				return
			}

			// Validate against device repository if repo is provided
			var record *storage.DeviceRecord
			if repo != nil {
				record, err = repo.GetDevice(identity)
				if err != nil || !repo.IsDeviceActive(identity) {
					log.Printf("[MTLS-AUTH] ❌ Device %q from %s rejected: unauthorized or revoked in registry", identity, r.RemoteAddr)
					http.Error(w, "Device is unauthorized or revoked", http.StatusForbidden)
					return
				}

				serial := clientCert.SerialNumber.String()
				if repo.IsSerialRevoked(serial) {
					log.Printf("[MTLS-AUTH] ❌ Device %q from %s rejected: certificate serial %s is revoked", identity, r.RemoteAddr, serial)
					http.Error(w, "Device certificate is revoked", http.StatusForbidden)
					return
				}

				// The presented certificate must be the currently issued one; a
				// stale certificate from before a re-enrollment is rejected.
				if record.CertSerial != serial {
					log.Printf("[MTLS-AUTH] ❌ Device %q from %s rejected: certificate serial %s is not current (expected %s)", identity, r.RemoteAddr, serial, record.CertSerial)
					http.Error(w, "Device certificate is not current", http.StatusForbidden)
					return
				}
			}

			label := ""
			if record != nil {
				label = record.Label
			}

			log.Printf("[MTLS-AUTH] ✅ Authenticated device %q (Serial=%s) from %s", identity, clientCert.SerialNumber.String(), r.RemoteAddr)

			identityCtx := &DeviceIdentity{
				Identity:   identity,
				Label:      label,
				CertSerial: clientCert.SerialNumber.String(),
				Record:     record,
			}

			ctx := context.WithValue(r.Context(), DeviceContextKey, identityCtx)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetDeviceIdentity extracts the DeviceIdentity from the request context.
func GetDeviceIdentity(ctx context.Context) (*DeviceIdentity, bool) {
	identity, ok := ctx.Value(DeviceContextKey).(*DeviceIdentity)
	return identity, ok && identity != nil
}
