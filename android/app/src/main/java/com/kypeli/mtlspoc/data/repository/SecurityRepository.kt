package com.kypeli.mtlspoc.data.repository

import android.util.Base64
import android.util.Log
import com.kypeli.mtlspoc.data.api.EnrollmentApi
import com.kypeli.mtlspoc.data.api.ProtectedApi
import com.kypeli.mtlspoc.data.model.EnrollRequest
import com.kypeli.mtlspoc.data.model.EnrollResponse
import com.kypeli.mtlspoc.data.model.ProtectedResponse
import com.kypeli.mtlspoc.di.DeviceId
import com.kypeli.mtlspoc.di.ProtectedBaseUrl
import com.kypeli.mtlspoc.security.CsrGenerator
import com.kypeli.mtlspoc.security.HardwareSecurityLevel
import com.kypeli.mtlspoc.security.KeystoreManager
import com.kypeli.mtlspoc.security.MtlsSocketFactoryBuilder
import dev.zacsweers.metro.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
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
) {
    private var protectedApi: ProtectedApi? = null

    private var cachedClientChain: Array<X509Certificate>? = null

    fun isEnrolled(): Boolean =
        keystoreManager.hasKey() && !keystoreManager.getClientCertificatePem().isNullOrBlank()

    fun getSecurityLevel(): HardwareSecurityLevel? =
        if (keystoreManager.hasKey()) {
            // TODO: StrongBox detection via Keystore info or previously stored result. StrongBox
            // key only supported in Android 31+.
            HardwareSecurityLevel.TEE
        } else {
            null
        }

    /**
     * Executes the full enrollment lifecycle:
     * 1. Fetches challenge nonce from enrollment backend (:8080/api/v1/enroll/challenge)
     * 2. Mints hardware-backed EC keypair with attestation in StrongBox or TEE
     * 3. Constructs & hardware-signs PKCS#10 CSR
     * 4. Transmits CSR + Attestation chain to backend
     * 5. Caches the returned CA-signed certificate chain in app storage
     *    (the AndroidKeyStore cannot attach a chain to a hardware-backed key)
     */
    suspend fun enroll(forceStrongBox: Boolean = true): EnrollmentResult =
        withContext(Dispatchers.IO) {
            Log.d(TAG, "Requesting enrollment challenge from server...")
            val challengeResponse = enrollmentApi.getChallenge()
            val challengeBytes = Base64.decode(challengeResponse.challenge, Base64.DEFAULT)

            Log.d(TAG, "Generating hardware key with attestation challenge...")
            val keyGenResult =
                keystoreManager.generateKeyPairWithAttestation(
                    challenge = challengeBytes,
                    forceStrongBox = forceStrongBox,
                )

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
            cachedClientChain = installedChain.filterIsInstance<X509Certificate>().toTypedArray()
            keystoreManager.saveClientCertificatePem(enrollResponse.clientCertificate)
            keystoreManager.saveCaCertificatePem(
                enrollResponse.caCertificate ?: enrollResponse.certificateChain?.lastOrNull(),
            )

            EnrollmentResult(
                securityLevel = keyGenResult.securityLevel,
                certificateChain = installedChain,
            )
        }

    /**
     * Prepares the mTLS OkHttpClient and executes a protected ping call over mTLS 1.3
     *
     * The trust anchor for the backend's private CA is resolved from
     * [caCertificatePemOrDer] (explicit override) or the CA PEM persisted at enrollment.
     * The client certificate chain is served from app storage by the custom KeyManager.
     */
    suspend fun pingProtected(caCertificatePemOrDer: ByteArray? = null): ProtectedResponse =
        withContext(Dispatchers.IO) {
            val api =
                protectedApi ?: run {
                    val caBytes =
                        caCertificatePemOrDer
                            ?: keystoreManager.getCaCertificatePem()?.toByteArray(Charsets.UTF_8)
                    val caStream = caBytes?.let { ByteArrayInputStream(it) }
                    val sslConfig =
                        MtlsSocketFactoryBuilder(
                            keystoreManager.getKeyStore(),
                            keystoreManager.getKeyAlias(),
                            resolveClientChain(),
                            logger = { msg -> Log.d(TLS_DIAG_TAG, msg) },
                        ).build(caStream)

                    val logging =
                        HttpLoggingInterceptor().apply {
                            level = HttpLoggingInterceptor.Level.BASIC
                        }
                    val mtlsClient =
                        OkHttpClient
                            .Builder()
                            .addInterceptor(logging)
                            .sslSocketFactory(sslConfig.sslSocketFactory, sslConfig.trustManager)
                            .build()

                    ProtectedApi(protectedBaseUrl, mtlsClient).also { protectedApi = it }
                }

            api.ping()
        }

    /**
     * Returns the CA-signed client certificate chain from the enrollment cache, lazily
     * restored from persisted PEM when the process was recreated. The chain is [leaf, ca].
     */
    private fun resolveClientChain(): Array<X509Certificate>? {
        cachedClientChain?.let { return it }

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
        cachedClientChain = chain
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
    }
}
