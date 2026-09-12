package com.kypeli.mtlspoc.security

import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import androidx.core.content.edit
import dev.zacsweers.metro.Inject
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

@Inject
class KeystoreManager(
    private val context: Context,
    private val keyAlias: String = DEFAULT_ALIAS,
) {
    private val keyStore: KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null)
        }

    private val trustPrefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val aliasA = "${keyAlias}_a"
    private val aliasB = "${keyAlias}_b"

    /**
     * Returns the alias currently holding the active device identity key.
     */
    fun getKeyAlias(): String {
        val stored = trustPrefs.getString(KEY_ACTIVE_ALIAS, aliasA)
        return if (stored == aliasA || stored == aliasB) stored else aliasA
    }

    private fun inactiveAlias(): String = if (getKeyAlias() == aliasA) aliasB else aliasA

    /**
     * Generates a secp256r1 hardware keypair with an attestation challenge nonce
     * under the currently inactive slot. Attempts StrongBox first; if unavailable,
     * falls back to TEE.
     *
     * The active identity is never touched during generation: the newly generated
     * key only becomes active when [activatePendingKey] is called after a successful
     * enrollment, so a failed enrollment cannot destroy the existing identity.
     */
    fun generateKeyPairWithAttestation(
        challenge: ByteArray,
        forceStrongBox: Boolean = true,
    ): KeyGenerationResult {
        val targetAlias = inactiveAlias()

        // Remove any stale key left by a previous interrupted enrollment; the
        // active identity remains untouched until the new enrollment succeeds.
        if (keyStore.containsAlias(targetAlias)) {
            keyStore.deleteEntry(targetAlias)
        }

        var securityLevel = HardwareSecurityLevel.STRONGBOX

        val keyPair =
            try {
                if (forceStrongBox && hasStrongBoxFeature()) {
                    generateEcKey(alias = targetAlias, isStrongBox = true, challenge = challenge)
                } else {
                    securityLevel = HardwareSecurityLevel.TEE
                    generateEcKey(alias = targetAlias, isStrongBox = false, challenge = challenge)
                }
            } catch (e: Exception) {
                if (isStrongBoxUnavailable(e)) {
                    Log.w(TAG, "StrongBox unavailable, falling back to TEE: ${e.message}")
                    securityLevel = HardwareSecurityLevel.TEE
                    generateEcKey(alias = targetAlias, isStrongBox = false, challenge = challenge)
                } else {
                    throw e
                }
            }

        val certChain = keyStore.getCertificateChain(targetAlias)?.toList() ?: emptyList()
        return KeyGenerationResult(
            keyPair = keyPair,
            attestationChain = certChain,
            securityLevel = securityLevel,
        )
    }

    /**
     * Promotes the newly generated key to the active slot and deletes the
     * superseded identity. Call only after a successful enrollment.
     */
    fun activatePendingKey() {
        val pending = inactiveAlias()
        val previous = getKeyAlias()
        if (previous != pending && keyStore.containsAlias(previous)) {
            keyStore.deleteEntry(previous)
        }
        trustPrefs.edit { putString(KEY_ACTIVE_ALIAS, pending) }
    }

    /**
     * Discards the newly generated key after a failed enrollment; the previous
     * identity remains active.
     */
    fun discardPendingKey() {
        val pending = inactiveAlias()
        if (keyStore.containsAlias(pending)) {
            keyStore.deleteEntry(pending)
        }
    }

    private fun generateEcKey(
        alias: String,
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
                    alias,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                ).setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_NONE)
                .setAttestationChallenge(challenge)

        if (isStrongBox) {
            specBuilder.setIsStrongBoxBacked(true)
        }

        kpg.initialize(specBuilder.build())
        return kpg.generateKeyPair()
    }

    private fun hasStrongBoxFeature(): Boolean = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    /**
     * Detects StrongBox unavailability by walking the whole cause chain: vendor
     * implementations frequently wrap [StrongBoxUnavailableException] in
     * ProviderException or throw generic ProviderException with a message.
     */
    private fun isStrongBoxUnavailable(error: Throwable): Boolean {
        var current: Throwable? = error
        var depth = 0
        while (current != null && depth < MAX_CAUSE_DEPTH) {
            if (current is StrongBoxUnavailableException) {
                return true
            }
            val msg = current.message?.lowercase() ?: ""
            if (msg.contains("strongbox") &&
                (msg.contains("unavailable") || msg.contains("not supported") || msg.contains("lack of"))
            ) {
                return true
            }
            current = current.cause
            depth++
        }
        return false
    }

    fun hasKey(): Boolean = keyStore.containsAlias(getKeyAlias())

    /**
     * Persists the backend CA certificate (public data) returned at enrollment so the mTLS
     * client can anchor server trust without depending on AndroidKeyStore chain ordering.
     */
    fun saveCaCertificatePem(pem: String?) {
        trustPrefs
            .edit {
                if (pem == null) remove(KEY_CA_PEM) else putString(KEY_CA_PEM, pem)
            }
    }

    fun getCaCertificatePem(): String? = trustPrefs.getString(KEY_CA_PEM, null)

    /**
     * Persists the CA-signed client leaf certificate (public data) returned at enrollment.
     * The client cert chain is deliberately held by the app rather than installed into the
     * AndroidKeyStore: on keystore2 (Android 12+/17), `setKeyEntry` cannot attach a chain to
     * a hardware-backed key ("Operation not supported because key encoding is unknown").
     */
    fun saveClientCertificatePem(pem: String?) {
        trustPrefs
            .edit {
                if (pem == null) remove(KEY_CLIENT_PEM) else putString(KEY_CLIENT_PEM, pem)
            }
    }

    fun getClientCertificatePem(): String? = trustPrefs.getString(KEY_CLIENT_PEM, null)

    /**
     * Persists the hardware security level reported during key generation so the
     * StrongBox vs TEE badge survives process recreation.
     */
    fun saveSecurityLevel(level: HardwareSecurityLevel?) {
        trustPrefs
            .edit {
                if (level == null) remove(KEY_SECURITY_LEVEL) else putString(KEY_SECURITY_LEVEL, level.name)
            }
    }

    fun getStoredSecurityLevel(): HardwareSecurityLevel? =
        trustPrefs.getString(KEY_SECURITY_LEVEL, null)?.let { stored ->
            runCatching { HardwareSecurityLevel.valueOf(stored) }.getOrNull()
        }

    /**
     * Deletes every identity key slot and clears all persisted trust state.
     */
    fun deleteKey() {
        for (alias in listOf(aliasA, aliasB, keyAlias)) {
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
        }
        trustPrefs
            .edit {
                remove(KEY_ACTIVE_ALIAS)
                remove(KEY_CA_PEM)
                remove(KEY_CLIENT_PEM)
                remove(KEY_SECURITY_LEVEL)
            }
    }

    fun getKeyStore(): KeyStore = keyStore

    data class KeyGenerationResult(
        val keyPair: KeyPair,
        val attestationChain: List<Certificate>,
        val securityLevel: HardwareSecurityLevel,
    )

    companion object {
        private const val TAG = "KeystoreManager"
        private const val PREFS_NAME = "mtls_trust_store"
        private const val KEY_CA_PEM = "backend_ca_pem"
        private const val KEY_CLIENT_PEM = "client_cert_pem"
        private const val KEY_ACTIVE_ALIAS = "active_alias"
        private const val KEY_SECURITY_LEVEL = "hardware_security_level"
        private const val MAX_CAUSE_DEPTH = 8
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val DEFAULT_ALIAS = "mtls_client_identity"
    }
}
