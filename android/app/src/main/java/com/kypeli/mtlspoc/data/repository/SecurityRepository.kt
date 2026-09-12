package com.kypeli.mtlspoc.data.repository

import android.util.Base64
import android.util.Log
import com.kypeli.mtlspoc.data.api.EnrollmentApi
import com.kypeli.mtlspoc.data.api.ProtectedApi
import com.kypeli.mtlspoc.data.model.EnrollRequest
import com.kypeli.mtlspoc.data.model.EnrollResponse
import com.kypeli.mtlspoc.data.model.ProtectedResponse
import com.kypeli.mtlspoc.di.DebugLoggingEnabled
import com.kypeli.mtlspoc.di.DeviceId
import com.kypeli.mtlspoc.di.ProtectedBaseUrl
import com.kypeli.mtlspoc.security.CsrGenerator
import com.kypeli.mtlspoc.security.HardwareSecurityLevel
import com.kypeli.mtlspoc.security.KeystoreManager
import com.kypeli.mtlspoc.security.MtlsSocketFactoryBuilder
import dev.zacsweers.metro.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.TlsVersion
import okhttp3.logging.HttpLoggingInterceptor
import java.io.ByteArrayInputStream
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

@Inject
class SecurityRepository(
    private val keystoreManager: KeystoreManager,
    private val enrollmentApi: EnrollmentApi,
    @param:ProtectedBaseUrl private val protectedBaseUrl: String,
    @param:DeviceId private val deviceId: String,
    @param:DebugLoggingEnabled private val debugLoggingEnabled: Boolean,
) {
    private val clientLock = Any()

    private var protectedApi: ProtectedApi? = null

    private var cachedClientChain: Array<X509Certificate>? = null

    fun isEnrolled(): Boolean =
        keystoreManager.hasKey() && !keystoreManager.getClientCertificatePem().isNullOrBlank()

    fun getSecurityLevel(): HardwareSecurityLevel? =
        if (keystoreManager.hasKey()) {
            keystoreManager.getStoredSecurityLevel()
        } else {
            null
        }

    /**
     * Executes the full enrollment lifecycle:
     * 1. Fetches challenge nonce from enrollment backend (:8080/api/v1/enroll/challenge)
     * 2. Mints hardware-backed EC keypair with attestation in StrongBox or TEE,
     *    under a separate alias slot so the current identity is untouched
     * 3. Constructs & hardware-signs PKCS#10 CSR
     * 4. Transmits CSR + Attestation chain to backend
     * 5. On success: persists the returned CA-signed certificate chain, activates
     *    the new key slot, and invalidates the cached mTLS client so subsequent
     *    pings present the fresh certificate
     * On any failure the new key slot is discarded and the previous identity
     * remains active.
     */
    suspend fun enroll(forceStrongBox: Boolean = true): EnrollmentResult =
        withContext(Dispatchers.IO) {
            // Invalidate any cached mTLS client built around the previous
            // certificate chain before minting a new key.
            invalidateClient()

            Log.d(TAG, "Requesting enrollment challenge from server...")
            val challengeResponse = enrollmentApi.getChallenge()
            val challengeBytes = Base64.decode(challengeResponse.challenge, Base64.DEFAULT)

            Log.d(TAG, "Generating hardware key with attestation challenge...")
            val keyGenResult =
                keystoreManager.generateKeyPairWithAttestation(
                    challenge = challengeBytes,
                    forceStrongBox = forceStrongBox,
                )

            try {
                Log.d(TAG, "Constructing hardware-signed PKCS#10 CSR for device: $deviceId...")
                val csrDer =
                    CsrGenerator.generateCsrDer(
                        subjectCommonName = deviceId,
                        privateKey = keyGenResult.keyPair.private,
                        publicKey = keyGenResult.keyPair.public,
                    )
                val csrBase64 = Base64.encodeToString(csrDer, Base64.NO_WRAP)

                val attestationChainBase64 =
                    keyGenResult.attestationChain.map { cert ->
                        Base64.encodeToString(cert.encoded, Base64.NO_WRAP)
                    }

                val enrollRequest =
                    EnrollRequest(
                        deviceId = deviceId,
                        csr = csrBase64,
                        attestationChain = attestationChainBase64,
                    )

                Log.d(TAG, "Submitting enrollment request to backend...")
                val enrollResponse = enrollmentApi.enroll(enrollRequest)

                Log.d(TAG, "Caching issued client certificate chain for mTLS...")
                val installedChain = parseCertificateChain(enrollResponse)
                synchronized(clientLock) {
                    cachedClientChain = installedChain.filterIsInstance<X509Certificate>().toTypedArray()
                }
                keystoreManager.saveClientCertificatePem(enrollResponse.clientCertificate)
                keystoreManager.saveCaCertificatePem(
                    enrollResponse.caCertificate ?: enrollResponse.certificateChain?.lastOrNull(),
                )

                // Only after the backend accepted the enrollment do we swap the
                // active key slot to the freshly generated identity.
                keystoreManager.activatePendingKey()
                keystoreManager.saveSecurityLevel(keyGenResult.securityLevel)

                EnrollmentResult(
                    securityLevel = keyGenResult.securityLevel,
                    certificateChain = installedChain,
                )
            } catch (e: Exception) {
                keystoreManager.discardPendingKey()
                throw e
            }
        }

    /**
     * Prepares the mTLS OkHttpClient and executes a protected ping call over mTLS 1.3
     *
     * The trust anchor for the backend's private CA is resolved from
     * [caCertificatePemOrDer] (explicit override) or the CA PEM persisted at enrollment.
     * The client certificate chain is served from app storage by the custom KeyManager.
     *
     * Trust anchor note: the backend CA certificate is adopted from the enrollment
     * response (trust-on-first-use). Release builds anchor enrollment itself to
     * system CAs via the network security config; debug builds additionally trust
     * the bundled development CA.
     */
    suspend fun pingProtected(caCertificatePemOrDer: ByteArray? = null): ProtectedResponse =
        withContext(Dispatchers.IO) {
            val api =
                synchronized(clientLock) {
                    protectedApi ?: buildProtectedApi(caCertificatePemOrDer).also { protectedApi = it }
                }

            api.ping()
        }

    private fun buildProtectedApi(caCertificatePemOrDer: ByteArray?): ProtectedApi {
        val caBytes =
            caCertificatePemOrDer
                ?: keystoreManager.getCaCertificatePem()?.toByteArray(Charsets.UTF_8)
        val caStream = caBytes?.let { ByteArrayInputStream(it) }
        val sslConfig =
            MtlsSocketFactoryBuilder(
                keystoreManager.getKeyStore(),
                keystoreManager.getKeyAlias(),
                resolveClientChain(),
                logger = if (debugLoggingEnabled) {
                    { msg -> Log.d(TLS_DIAG_TAG, msg) }
                } else {
                    { _ -> }
                },
            ).build(caStream)

        val builder =
            OkHttpClient
                .Builder()
                .sslSocketFactory(sslConfig.sslSocketFactory, sslConfig.trustManager)
                .connectionSpecs(listOf(TLS_1_3_ONLY))

        if (debugLoggingEnabled) {
            builder.addInterceptor(
                HttpLoggingInterceptor().apply {
                    level = HttpLoggingInterceptor.Level.BASIC
                },
            )
        }

        val mtlsClient = builder.build()

        return ProtectedApi(protectedBaseUrl, mtlsClient)
    }

    /**
     * Invalidates the cached mTLS client and certificate chain. Must be called
     * before minting a new key so pings never present a stale certificate.
     */
    private fun invalidateClient() {
        synchronized(clientLock) {
            protectedApi = null
            cachedClientChain = null
        }
    }

    /**
     * Returns the CA-signed client certificate chain from the enrollment cache, lazily
     * restored from persisted PEM when the process was recreated. The chain is [leaf, ca].
     */
    private fun resolveClientChain(): Array<X509Certificate>? {
        synchronized(clientLock) {
            cachedClientChain?.let { return it }
        }

        val leafPem = keystoreManager.getClientCertificatePem() ?: return null
        val caPem = keystoreManager.getCaCertificatePem()

        val cf = CertificateFactory.getInstance("X.509")
        val leaf =
            cf.generateCertificate(ByteArrayInputStream(leafPem.toByteArray(Charsets.UTF_8)))
                as X509Certificate
        val chain =
            if (caPem == null) {
                arrayOf(leaf)
            } else {
                val ca =
                    cf.generateCertificate(ByteArrayInputStream(caPem.toByteArray(Charsets.UTF_8)))
                        as X509Certificate
                arrayOf(leaf, ca)
            }
        synchronized(clientLock) {
            cachedClientChain = chain
        }
        return chain
    }

    private fun parseCertificateChain(response: EnrollResponse): List<Certificate> {
        val cf = CertificateFactory.getInstance("X.509")

        if (!response.certificateChain.isNullOrEmpty()) {
            return response.certificateChain.map { certStr ->
                parseSingleCertificate(cf, certStr)
            }
        }

        val chain = mutableListOf<Certificate>()
        chain.add(parseSingleCertificate(cf, response.clientCertificate))
        response.caCertificate?.let { caStr ->
            chain.add(parseSingleCertificate(cf, caStr))
        }
        return chain
    }

    private fun parseSingleCertificate(
        cf: CertificateFactory,
        certStr: String,
    ): Certificate {
        val cleaned = certStr.trim()
        val bytes =
            if (cleaned.startsWith("-----BEGIN CERTIFICATE-----")) {
                cleaned.toByteArray(Charsets.UTF_8)
            } else {
                Base64.decode(cleaned, Base64.DEFAULT)
            }
        return cf.generateCertificate(ByteArrayInputStream(bytes))
    }

    data class EnrollmentResult(
        val securityLevel: HardwareSecurityLevel,
        val certificateChain: List<Certificate>,
    )

    companion object {
        private const val TAG = "SecurityRepository"
        private const val TLS_DIAG_TAG = "TLS-Client"

        /**
         * Connection spec restricting the mTLS client to TLS 1.3 exclusively; OkHttp's
         * default specs would still offer TLS 1.2 even with a TLSv1.3 SSLContext.
         */
        val TLS_1_3_ONLY: ConnectionSpec =
            ConnectionSpec
                .Builder(ConnectionSpec.MODERN_TLS)
                .tlsVersions(TlsVersion.TLS_1_3)
                .build()
    }
}
