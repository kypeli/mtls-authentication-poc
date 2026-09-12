package com.kypeli.mtlspoc.security

import java.io.InputStream
import java.net.Socket
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509TrustManager

class MtlsSocketFactoryBuilder(
    private val keyStore: KeyStore,
    private val clientAlias: String = KeystoreManager.DEFAULT_ALIAS,
    private val clientCertificateChain: Array<X509Certificate>? = null,
    private val logger: (String) -> Unit = {},
) {

    /**
     * Builds SSLSocketFactory and X509TrustManager configured for mTLS 1.3
     * using the specified CA certificate inputStream (or standard trust manager if caCertInputStream is null).
     */
    fun build(caCertInputStream: InputStream? = null): MtlsSslConfig {
        val keyManager = createKeyManager()
        val trustManager = createTrustManager(caCertInputStream)

        val sslContext = SSLContext.getInstance("TLSv1.3")
        sslContext.init(arrayOf<KeyManager>(keyManager), arrayOf(trustManager), SecureRandom())

        return MtlsSslConfig(
            sslSocketFactory = sslContext.socketFactory,
            trustManager = trustManager,
            keyManager = keyManager
        )
    }

    private fun createKeyManager(): X509ExtendedKeyManager {
        return object : X509ExtendedKeyManager() {
            override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String> {
                return arrayOf(clientAlias)
            }

            override fun chooseClientAlias(
                keyType: Array<out String>?,
                issuers: Array<out Principal>?,
                socket: Socket?
            ): String {
                logger("chooseClientAlias keyType=${keyType?.joinToString()} issuers=${issuers?.map { it.name }?.joinToString()}")
                return clientAlias
            }

            override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? {
                return null
            }

            override fun chooseServerAlias(
                keyType: String?,
                issuers: Array<out Principal>?,
                socket: Socket?
            ): String? {
                return null
            }

            override fun getCertificateChain(alias: String?): Array<X509Certificate>? {
                val targetAlias = alias ?: clientAlias
                clientCertificateChain?.let {
                    logger("getCertificateChain($targetAlias) -> explicit chain of ${it.size}")
                    return it
                }
                val chain = keyStore.getCertificateChain(targetAlias)
                logger("getCertificateChain($targetAlias) -> keystore chain of ${chain?.size ?: 0}")
                return chain?.mapNotNull { it as? X509Certificate }?.toTypedArray()
            }

            override fun getPrivateKey(alias: String?): PrivateKey? {
                val targetAlias = alias ?: clientAlias
                val key = keyStore.getKey(targetAlias, null) as? PrivateKey
                logger("getPrivateKey($targetAlias) -> ${key?.javaClass?.name ?: "null"}")
                return key
            }
        }
    }

    private fun createTrustManager(caCertInputStream: InputStream?): X509TrustManager {
        val delegate =
            if (caCertInputStream != null) {
                val cf = CertificateFactory.getInstance("X.509")
                val caCert = cf.generateCertificate(caCertInputStream) as X509Certificate
                logger("trust anchor = ${caCert.subjectDN}")

                val caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                    load(null, null)
                    setCertificateEntry("backend_ca", caCert)
                }

                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
                    init(caKeyStore)
                }
            } else {
                logger("trust anchor = SYSTEM")
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
                    init(null as KeyStore?)
                }
            }

        val impl = delegate.trustManagers.filterIsInstance<X509TrustManager>().firstOrNull()
            ?: throw IllegalStateException("No X509TrustManager found")
        logger("trust managers acquired: ${delegate.trustManagers.map { it.javaClass.simpleName }}")

        return object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                logger("checkClientTrusted len=${chain?.size} authType=$authType")
                impl.checkClientTrusted(chain, authType)
            }

            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                logger("checkServerTrusted len=${chain?.size} authType=$authType subject=${chain?.firstOrNull()?.subjectX500Principal?.name}")
                try {
                    impl.checkServerTrusted(chain, authType)
                    logger("checkServerTrusted OK")
                } catch (t: Throwable) {
                    logger("checkServerTrusted FAILED: ${t.javaClass.simpleName}: ${t.message}")
                    throw t
                }
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> {
                val issuers = impl.acceptedIssuers
                logger("getAcceptedIssuers count=${issuers.size} ${issuers.map { it.subjectX500Principal.name }}")
                return issuers
            }
        }
    }

    data class MtlsSslConfig(
        val sslSocketFactory: SSLSocketFactory,
        val trustManager: X509TrustManager,
        val keyManager: X509ExtendedKeyManager
    )
}
