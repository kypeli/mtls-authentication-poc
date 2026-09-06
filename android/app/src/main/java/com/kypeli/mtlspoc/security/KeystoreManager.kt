package com.kypeli.mtlspoc.security

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

class KeystoreManager(
    private val context: Context,
    private val keyAlias: String = DEFAULT_ALIAS,
) {
    private val keyStore: KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null)
        }

    /**
     * Generates a secp256r1 hardware keypair with an attestation challenge nonce.
     * Attempts StrongBox first; if unavailable, falls back to TEE.
     */
    fun generateKeyPairWithAttestation(
        challenge: ByteArray,
        forceStrongBox: Boolean = true,
    ): KeyGenerationResult {
        // Delete existing entry if any
        if (keyStore.containsAlias(keyAlias)) {
            keyStore.deleteEntry(keyAlias)
        }

        var securityLevel = HardwareSecurityLevel.STRONGBOX

        val keyPair =
            try {
                if (forceStrongBox && hasStrongBoxFeature()) {
                    generateEcKey(isStrongBox = true, challenge = challenge)
                } else {
                    securityLevel = HardwareSecurityLevel.TEE
                    generateEcKey(isStrongBox = false, challenge = challenge)
                }
            } catch (e: Exception) {
                if (isStrongBoxUnavailable(e)) {
                    Log.w(TAG, "StrongBox unavailable, falling back to TEE: ${e.message}")
                    securityLevel = HardwareSecurityLevel.TEE
                    generateEcKey(isStrongBox = false, challenge = challenge)
                } else {
                    throw e
                }
            }

        val certChain = keyStore.getCertificateChain(keyAlias)?.toList() ?: emptyList()
        return KeyGenerationResult(
            keyPair = keyPair,
            attestationChain = certChain,
            securityLevel = securityLevel,
        )
    }

    private fun generateEcKey(
        isStrongBox: Boolean,
        challenge: ByteArray,
    ): KeyPair {
        val kpg =
            KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                ANDROID_KEYSTORE,
            )

        val specBuilder =
            KeyGenParameterSpec
                .Builder(
                    keyAlias,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                ).setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)

        if (isStrongBox) {
            specBuilder.setIsStrongBoxBacked(true)
        }

        kpg.initialize(specBuilder.build())
        return kpg.generateKeyPair()
    }

    private fun hasStrongBoxFeature(): Boolean = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    private fun isStrongBoxUnavailable(e: Throwable): Boolean {
        if (e is StrongBoxUnavailableException) {
            return true
        }
        val msg = e.message?.lowercase() ?: ""
        return msg.contains("strongbox") && (msg.contains("unavailable") || msg.contains("not supported"))
    }

    fun hasKey(): Boolean = keyStore.containsAlias(keyAlias)

    fun getPrivateKey(): PrivateKey? = keyStore.getKey(keyAlias, null) as? PrivateKey

    fun getCertificateChain(): List<Certificate>? = keyStore.getCertificateChain(keyAlias)?.toList()

    fun getLeafCertificate(): X509Certificate? = keyStore.getCertificate(keyAlias) as? X509Certificate

    /**
     * Installs the CA-signed certificate chain returned by the backend, linking it
     * to the existing hardware-backed private key entry in the AndroidKeyStore.
     */
    fun installCertificateChain(certificates: List<Certificate>) {
        val chainArray = certificates.toTypedArray()
        keyStore.setKeyEntry(keyAlias, null, chainArray)
        Log.i(TAG, "Successfully installed certificate chain of size ${chainArray.size} for alias $keyAlias")
    }

    fun deleteKey() {
        if (keyStore.containsAlias(keyAlias)) {
            keyStore.deleteEntry(keyAlias)
        }
    }

    fun getKeyStore(): KeyStore = keyStore

    fun getKeyAlias(): String = keyAlias

    data class KeyGenerationResult(
        val keyPair: KeyPair,
        val attestationChain: List<Certificate>,
        val securityLevel: HardwareSecurityLevel,
    )

    companion object {
        private const val TAG = "KeystoreManager"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val DEFAULT_ALIAS = "mtls_client_identity"
    }
}
