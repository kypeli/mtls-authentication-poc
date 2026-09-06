# Hardware-Backed Mutual TLS (mTLS) Proof of Concept

A production-grade Proof of Concept (PoC) demonstrating **Hardware-Backed Mutual TLS (mTLS 1.3)** on Android, utilizing **StrongBox Keymaster / KeyMint**, **Android Key Attestation**, and automated **PKCS#10 Certificate Signing Request (CSR)** generation.

---

## 🔒 Security Architecture & Motivation

Traditional mobile authentication mechanisms (bearer tokens, API keys, client certificates stored in software or app private files) are vulnerable to extraction via root access, memory dumping, hooking (Frida/Xposed), or supply-chain compromise.

This project implements **Zero-Trust Client Authentication** by ensuring:
1. **Hardware-Bound Private Keys**: Cryptographic key pairs (EC `secp256r1`) are generated directly inside tamper-resistant hardware (StrongBox dedicated HSM or ARM TrustZone TEE) and marked non-exportable.
2. **Zero Key Exposure**: Private key bytes never enter application memory or storage. Digital signatures (including the CSR and TLS 1.3 handshake challenge signatures) are computed entirely within the hardware enclave.
3. **Hardware Attestation**: During initial onboarding, the device proves to the backend that the key was legitimately minted inside genuine, secure Android hardware via Google's Hardware Attestation Certificate Chain.
4. **Automated Enterprise CA Enrollment**: The backend verifies attestation, extracts the device identity and public key from the CSR, and issues an X.509 client certificate signed by a trusted Enterprise CA.
5. **Seamless TLS 1.3 Client Handshake**: Android's `AndroidKeyStore` provider is integrated with OkHttp via a custom `X509ExtendedKeyManager`, allowing the OS to transparently sign client authentication challenges during the TLS 1.3 handshake.

```
+---------------------------------------------------------------------------------------------------------+
|                                              ANDROID DEVICE                                             |
|                                                                                                         |
|   +--------------------------+        +---------------------------+        +------------------------+   |
|   |       Compose UI         | <----> |       MainViewModel       | <----> |   SecurityRepository   |   |
|   +--------------------------+        +---------------------------+        +-----------+------------+   |
|                                                                                        |                |
|               +-----------------------+-------------------------+----------------------+                |
|               |                       |                         |                                       |
|               v                       v                         v                                       |
|       +---------------+       +---------------+       +--------------------+                            |
|       | KeystoreMgr   |       | CsrGenerator  |       | MtlsSocketFactory  |                            |
|       +-------+-------+       +-------+-------+       +---------+----------+                            |
|               |                       |                         |                                       |
|               | (attestation nonce)   | (in-hardware signing)   | (TLS 1.3 handshake)                   |
|               v                       v                         v                                       |
|   +-------------------------------------------------------------------------------------------------+   |
|   |                              HARDWARE ENCLAVE (AndroidKeyStore)                                 |   |
|   |       [StrongBox HSM (Titan M)  /  Trusted Execution Environment (ARM TrustZone TEE)]           |   |
|   |       • Key: EC secp256r1 (PURPOSE_SIGN | PURPOSE_VERIFY)                                       |   |
|   |       • Private Key CANNOT be exported, read, or modified                                       |   |
|   |       • Issues Google-signed Attestation Chain on generation                                    |   |
|   +-------------------------------------------------------------------------------------------------+   |
+---------------------------------------------------------------------------------------------------------+
                                                |
                                      HTTPS / mTLS 1.3
                                                |
                                                v
+---------------------------------------------------------------------------------------------------------+
|                                              BACKEND CA                                                 |
|                                                                                                         |
|   1. GET  /api/v1/enroll/challenge   --> Issues cryptographically random challenge nonce                |
|   2. POST /api/v1/enroll             --> Verifies Google Attestation Chain, Nonce, Boot State & CSR;    |
|                                          issues CA-signed X.509 Client Certificate                      |
|   3. GET  /api/v1/protected/ping     --> Authenticates device identity over Mutual TLS 1.3              |
+---------------------------------------------------------------------------------------------------------+
```

---

## 🚀 Protocol Flow

```mermaid
sequenceDiagram
    autonumber
    participant App as Android Client
    participant HW as Hardware Enclave (StrongBox/TEE)
    participant Srv as Backend Enrollment API
    participant TLS as Protected mTLS Endpoint

    Note over App,Srv: Phase 1: Challenge & Hardware Key Generation
    App->>Srv: GET /api/v1/enroll/challenge
    Srv-->>App: { challenge: "nonce_base64", expires_in: 300 }

    App->>HW: KeyGenParameterSpec (EC secp256r1, challenge, StrongBox fallback to TEE)
    HW-->>App: KeyPair + Google Attestation Certificate Chain

    Note over App,HW: Phase 2: In-Hardware CSR Generation
    App->>HW: Sign PKCS#10 CSR (CN=deviceId, SHA256withECDSA) via AndroidKeystoreSigner
    HW-->>App: Signed DER CSR (No private key touched)

    Note over App,Srv: Phase 3: Attestation Verification & Certificate Issuance
    App->>Srv: POST /api/v1/enroll { device_id, csr, attestation_chain }
    Note over Srv: 1. Verify Google Root CA & chain<br/>2. Match attestation challenge nonce<br/>3. Validate Keymaster properties (Rollback, TEE/StrongBox)<br/>4. Sign client cert with Device CA
    Srv-->>App: { client_certificate, ca_certificate, certificate_chain }

    Note over App,HW: Phase 4: Install Certificate Chain
    App->>HW: keyStore.setKeyEntry(alias, null, chainArray)

    Note over App,TLS: Phase 5: Mutual TLS 1.3 Communication
    App->>TLS: GET /api/v1/protected/ping (Client Hello)
    TLS-->>App: Server Hello + Certificate Request
    App->>HW: Compute TLS Handshake Signature over Hardware Private Key
    HW-->>App: Handshake Signature
    App-->>TLS: Client Certificate + Finished
    TLS-->>App: 200 OK { status: "ok", client_identity: "deviceId" }
```

---

## 📁 Repository Structure

```
.
├── README.md                           # Project documentation and architectural guide
├── AGENTS.md                           # Instructions and guidelines for autonomous AI agents
├── android/                            # Android native client application
│   ├── app/
│   │   ├── build.gradle.kts            # App-level build config (Kotlin 2.2+, AGP 9.4+)
│   │   └── src/
│   │       ├── debug/
│   │       │   └── res/raw/debug_ca.crt      # Local Root CA for automatic Android debug trust
│   │       ├── main/
│   │       │   ├── AndroidManifest.xml
│   │       │   ├── res/xml/
│   │       │   │   └── network_security_config.xml # System CAs (prod) & @raw/debug_ca (debug)
│   │       │   └── java/com/kypeli/mtlspoc/
│   │       │       ├── MainActivity.kt # Compose entry point
│   │       │       ├── data/
│   │       │       │   ├── api/        # EnrollmentApi & ProtectedApi (OkHttp + Moshi)
│   │       │       │   ├── model/      # Moshi JSON data classes
│   │       │       │   └── repository/ # SecurityRepository (Orchestrates onboarding & mTLS)
│   │       │       ├── security/
│   │       │       │   ├── AndroidKeystoreSigner.kt      # BouncyCastle ContentSigner bridge
│   │       │       │   ├── CsrGenerator.kt               # PKCS#10 DER CSR generator
│   │       │       │   ├── HardwareSecurityLevel.kt      # StrongBox vs TEE enum
│   │       │       │   ├── KeystoreManager.kt            # Key generation, attestation & storage
│   │       │       │   └── MtlsSocketFactoryBuilder.kt   # TLS 1.3 SSLContext & KeyManager
│   │       │       └── ui/
│   │       │           ├── MainViewModel.kt              # State orchestration (Coroutines + Flow)
│   │       │           └── UiState.kt                    # UI state hierarchy
│   │       └── test/
│   │           └── java/com/kypeli/mtlspoc/
│   │               ├── CsrGeneratorTest.kt               # Unit tests for CSR generation & validation
│   │               └── MtlsSocketFactoryBuilderTest.kt   # Unit tests for SSL factory & trust manager
│   ├── gradle/
│   │   └── libs.versions.toml          # Gradle version catalog
│   ├── build.gradle.kts
│   └── settings.gradle.kts
└── backend/                            # Go backend service (Dual HTTPS/mTLS listeners)
```

---

## 🧩 Android Implementation Details

### 1. `KeystoreManager`
- Generates standard elliptic curve keys using `KeyProperties.KEY_ALGORITHM_EC` with curve `secp256r1`.
- Proactively checks `PackageManager.FEATURE_STRONGBOX_KEYSTORE` and sets `specBuilder.setIsStrongBoxBacked(true)`.
- If StrongBox hardware is unavailable or throws `StrongBoxUnavailableException`, automatically falls back to Trusted Execution Environment (`TEE`).
- Embeds the server's challenge nonce into the attestation extension using `.setAttestationChallenge(challenge)`.
- Installs the server's CA-signed certificate chain back into the hardware key entry using `keyStore.setKeyEntry(keyAlias, null, chainArray)`.

### 2. `AndroidKeystoreSigner`
- Implements Bouncy Castle's `org.bouncycastle.operator.ContentSigner`.
- Buffers the PKCS#10 data to sign and invokes `java.security.Signature.getInstance("SHA256withECDSA")` initialized with the `PrivateKey` handle.
- Enables in-hardware CSR generation without extracting or handling private key material.

### 3. `MtlsSocketFactoryBuilder`
- Implements `javax.net.ssl.X509ExtendedKeyManager` targeting the client certificate alias.
- Overrides `chooseClientAlias`, `getPrivateKey`, and `getCertificateChain` to supply the hardware-backed key during TLS 1.3 handshake negotiation.
- Configures `SSLContext.getInstance("TLSv1.3")` and initializes trust against the custom backend CA certificate.

### 4. `SecurityRepository`
- Coordinates the complete sequence:
  1. Requests challenge from `EnrollmentApi.getChallenge()`
  2. Generates hardware keypair via `KeystoreManager`
  3. Constructs hardware-signed CSR via `CsrGenerator`
  4. Dispatches `EnrollRequest` with base64-encoded CSR and attestation chain
  5. Parses response and persists certificate chain into the AndroidKeyStore
  6. Configures authenticated `ProtectedApi` instance over mTLS

---

## 📡 Backend API Contract

The backend service exposes three primary endpoints:

### 1. Challenge Nonce Generation
* **Endpoint**: `GET /api/v1/enroll/challenge`
* **Response**:
```json
{
  "challenge": "dGhpcy1pcy1hLXJhbmRvbS1ub25jZQ==",
  "expires_in": 300
}
```

### 2. Device Enrollment & Attestation Verification
* **Endpoint**: `POST /api/v1/enroll`
* **Content-Type**: `application/json`
* **Request**:
```json
{
  "device_id": "device_uuid_or_hardware_identifier",
  "csr": "MIIBOzCB... (Base64-encoded DER PKCS#10 CSR)",
  "attestation_chain": [
    "MII... (Base64-encoded DER leaf certificate with Android attestation extension)",
    "MII... (Intermediate certificates)",
    "MII... (Google Root CA certificate)"
  ]
}
```
* **Response**:
```json
{
  "client_certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "ca_certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "certificate_chain": [
    "MIIC...",
    "MIID..."
  ]
}
```

### 3. Protected Resource Access (mTLS 1.3 Required)
* **Endpoint**: `GET /api/v1/protected/ping`
* **Security**: Mutual TLS handshake required; client must present valid CA-issued certificate.
* **Response**:
```json
{
  "status": "ok",
  "message": "mTLS connection successful",
  "client_identity": "device_uuid_or_hardware_identifier",
  "timestamp": 1725612345
}
```

---

## 🛠️ Build & Development Setup

### Prerequisites
- **Java Development Kit (JDK)**: JDK 17 or JDK 21 (compatible with Android Studio Meerkat / Ladybug).
- **Android SDK**: Build Tools `37.0.0` (or `35.0.0+`), `compileSdk = 37`, `minSdk = 29`.
- **Physical Device (Recommended)**: For StrongBox testing, a physical device equipped with a hardware security chip (e.g. Google Pixel 3+ with Titan M/M2) is required. Emulators will execute under TEE or Software fallback.

### 🔐 Development Certificates & Android Debug Trust

During onboarding, standard Android clients connect to the enrollment endpoint (`https://<host>:8080`) over standard HTTPS without any pre-shared knowledge or pinning of `server.crt`.

To support frictionless local development and testing on emulators and physical devices without purchasing public Web PKI certificates:
- **Local CA & Server TLS Certificates**:
  Bootstrapped by running `make certgen` in `backend/`, which creates `backend/certs/ca.crt` (Root CA) and `backend/certs/server.crt` (SANs: `localhost`, `android.local`, `127.0.0.1`, `10.0.2.2`, `::1`).
- **Automatic Android Debug Trust (`debug_ca.crt`)**:
  The development Root CA (`backend/certs/ca.crt`) is placed in `android/app/src/debug/res/raw/debug_ca.crt`.
- **Network Security Config (`network_security_config.xml`)**:
  - **Release Builds (`<base-config>`)**: Strictly enforce Android's default `system` CAs. Production builds never bundle, pin, or trust private development certificates.
  - **Debug Builds (`<debug-overrides>`)**: Automatically trust `@raw/debug_ca` and `user` CAs. When building with `assembleDebug`, the app seamlessly trusts the local server certificate on `10.0.2.2:8080` (Android emulator host loopback) or `localhost:8080` out of the box with zero manual certificate installation.

### Android Client
To run unit tests:
```bash
cd android
./gradlew test
```

To build the debug APK:
```bash
cd android
./gradlew assembleDebug
```

### Backend Service (Go)
To build the server and certificate generation utility:
```bash
cd backend
make build
```

To run all backend unit and integration tests (with race detection):
```bash
cd backend
make test
```

To bootstrap local Root CA and Server TLS certificates:
```bash
cd backend
make certgen
```

To start the dual-listener backend server (:8080 HTTPS standard TLS enrollment & :8443 mTLS 1.3):
```bash
cd backend
make run
```

---

## 🗺️ Roadmap & Next Steps

- [x] Hardware-backed keypair generation with StrongBox and TEE fallback
- [x] Attestation challenge embedding
- [x] In-hardware PKCS#10 CSR signing via Bouncy Castle `ContentSigner`
- [x] TLS 1.3 `SSLSocketFactory` and `X509ExtendedKeyManager` integration
- [x] Complete client-side security repository and state machine
- [x] Unit test suite for CSR generation and SSL context construction
- [x] **Backend Service Implementation**: Production-grade Go backend with Google Attestation parsing (OID `1.3.6.1.4.1.11129.2.1.17`), in-process ECDSA P-256 CA, standard TLS enrollment on port 8080, and strict mTLS 1.3 listener on port 8443.
- [ ] **Interactive Compose UI**: Wire `MainViewModel` into `MainActivity` with enrollment state display, hardware security indicator, and ping action.
