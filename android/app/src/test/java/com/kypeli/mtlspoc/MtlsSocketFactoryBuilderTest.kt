package com.kypeli.mtlspoc

import com.kypeli.mtlspoc.data.repository.SecurityRepository
import com.kypeli.mtlspoc.security.MtlsSocketFactoryBuilder
import okhttp3.TlsVersion
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.net.InetAddress
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Principal
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

class MtlsSocketFactoryBuilderTest {

    @Test
    fun testBuildMtlsSocketFactory() {
        val (caCert, _, _, clientKeyPair, clientChain) = buildTestCertificates()

        val alias = "test_alias"
        val testKeyStore = buildClientKeyStore(alias, clientKeyPair, clientChain)

        val builder = MtlsSocketFactoryBuilder(testKeyStore, alias)
        val sslConfig = builder.build(ByteArrayInputStream(caCert.encoded))

        assertNotNull(sslConfig.sslSocketFactory)
        assertNotNull(sslConfig.trustManager)
        assertNotNull(sslConfig.trustManager.acceptedIssuers)
    }

    @Test
    fun testKeyManagerSuppliesHardwareAliasAndChain() {
        val (caCert, _, _, clientKeyPair, clientChain) = buildTestCertificates()

        val alias = "test_alias"
        val testKeyStore = buildClientKeyStore(alias, clientKeyPair, clientChain)

        val sslConfig = MtlsSocketFactoryBuilder(testKeyStore, alias).build(ByteArrayInputStream(caCert.encoded))
        val keyManager = sslConfig.keyManager

        val aliases = keyManager.getClientAliases("EC", null)
        assertNotNull(aliases)
        assertEquals(1, aliases!!.size)
        assertEquals(alias, aliases[0])

        assertEquals(alias, keyManager.chooseClientAlias(arrayOf("EC", "RSA"), null, null))

        val chain = keyManager.getCertificateChain(alias)
        assertNotNull(chain)
        assertEquals(clientChain.size, chain!!.size)
        assertSame(clientChain[0], chain[0])

        val privateKey = keyManager.getPrivateKey(alias)
        assertNotNull(privateKey)
        assertNull(keyManager.getPrivateKey("unknown_alias"))
        assertNull(keyManager.getServerAliases("RSA", null))
        assertNull(keyManager.chooseServerAlias("RSA", null, null))
    }

    @Test
    fun testFullTls13HandshakePresentsClientCertificate() {
        val (caCert, serverPair, serverCert, clientKeyPair, clientChain) = buildTestCertificates()

        val alias = "test_alias"
        val clientKeyStore = buildClientKeyStore(alias, clientKeyPair, clientChain)
        val sslConfig = MtlsSocketFactoryBuilder(clientKeyStore, alias).build(ByteArrayInputStream(caCert.encoded))

        // Server side: TLS 1.3 only, requiring a client certificate chained to the CA
        val serverKeyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setKeyEntry("server", serverPair.private, null, arrayOf(serverCert, caCert))
        }
        val serverTrustStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setCertificateEntry("ca", caCert)
        }
        val serverTmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
            init(serverTrustStore)
        }
        val serverTrustManager = serverTmf.trustManagers.filterIsInstance<X509TrustManager>().first()

        val serverKmf = javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm())
        serverKmf.init(serverKeyStore, null)
        val serverContext = SSLContext.getInstance("TLSv1.3")
        serverContext.init(serverKmf.keyManagers, arrayOf(serverTrustManager), SecureRandom())

        val serverSocket = serverContext.serverSocketFactory.createServerSocket(0, 1, InetAddress.getLoopbackAddress()) as SSLServerSocket
        serverSocket.needClientAuth = true
        serverSocket.enabledProtocols = arrayOf(TlsVersion.TLS_1_3.javaName)

        val serverReady = CountDownLatch(1)
        val handshakeDone = CountDownLatch(1)
        var serverPeerPrincipal: Principal? = null
        var serverProtocol: String? = null

        val serverThread = Thread {
            try {
                serverReady.countDown()
                serverSocket.accept().use { socket ->
                    val ssl = socket as SSLSocket
                    ssl.startHandshake()
                    serverProtocol = ssl.session.protocol
                    serverPeerPrincipal = ssl.session.peerPrincipal
                    ssl.inputStream.read()
                    ssl.outputStream.write(1)
                }
            } catch (_: Exception) {
            } finally {
                handshakeDone.countDown()
            }
        }
        serverThread.isDaemon = true
        serverThread.start()
        assertTrue(serverReady.await(5, TimeUnit.SECONDS))

        try {
            val clientSocket = sslConfig.sslSocketFactory.createSocket(
                InetAddress.getLoopbackAddress(),
                serverSocket.localPort,
            ) as SSLSocket
            clientSocket.startHandshake()

            assertEquals("TLSv1.3", clientSocket.session.protocol)

            clientSocket.outputStream.write(1)
            assertTrue(handshakeDone.await(5, TimeUnit.SECONDS))

            assertEquals("TLSv1.3", serverProtocol)
            assertNotNull("server must have received the client certificate", serverPeerPrincipal)
            clientSocket.close()
        } finally {
            serverSocket.close()
            serverThread.join(5_000)
        }
    }

    @Test
    fun testTls13OnlyConnectionSpec() {
        val spec = SecurityRepository.TLS_1_3_ONLY
        assertTrue(spec.isTls)
        val versions = spec.tlsVersions.orEmpty()
        assertEquals(1, versions.size)
        assertEquals(TlsVersion.TLS_1_3, versions[0])
    }

    // Helpers

    private data class TestCerts(
        val caCert: X509Certificate,
        val serverPair: KeyPair,
        val serverCert: X509Certificate,
        val clientPair: KeyPair,
        val clientChain: Array<X509Certificate>,
    )

    private fun buildTestCertificates(): TestCerts {
        val caPair = generateEcKeyPair()
        val caCert = signCertificate(
            subject = "CN=TestRootCA",
            publicKey = caPair.public,
            signerKey = caPair.private,
            isCa = true,
        )

        val serverPair = generateEcKeyPair()
        val serverCert = signCertificate(
            subject = "CN=localhost",
            publicKey = serverPair.public,
            signerKey = caPair.private,
            isCa = false,
            issuer = caCert,
        )

        val clientPair = generateEcKeyPair()
        val clientCert = signCertificate(
            subject = "CN=test-client",
            publicKey = clientPair.public,
            signerKey = caPair.private,
            isCa = false,
            issuer = caCert,
        )

        return TestCerts(
            caCert = caCert,
            serverPair = serverPair,
            serverCert = serverCert,
            clientPair = clientPair,
            clientChain = arrayOf(clientCert, caCert),
        )
    }

    private fun buildClientKeyStore(alias: String, keyPair: KeyPair, chain: Array<X509Certificate>): KeyStore =
        KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setKeyEntry(alias, keyPair.private, null, chain as Array<Certificate>)
        }

    private fun generateEcKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

    private fun signCertificate(
        subject: String,
        publicKey: java.security.PublicKey,
        signerKey: java.security.PrivateKey,
        isCa: Boolean,
        issuer: X509Certificate? = null,
    ): X509Certificate {
        val issuerName = issuer?.let { X500Name(it.subjectX500Principal.name) } ?: X500Name(subject)
        val subjectName = X500Name(subject)
        val builder = X509v3CertificateBuilder(
            issuerName,
            BigInteger(64, SecureRandom()),
            Date(System.currentTimeMillis() - 60_000),
            Date(System.currentTimeMillis() + 24 * 60 * 60 * 1000),
            subjectName,
            SubjectPublicKeyInfo.getInstance(publicKey.encoded),
        )
        if (isCa) {
            builder.addExtension(
                org.bouncycastle.asn1.x509.Extension.basicConstraints,
                true,
                org.bouncycastle.asn1.x509.BasicConstraints(true),
            )
            builder.addExtension(
                org.bouncycastle.asn1.x509.Extension.keyUsage,
                true,
                org.bouncycastle.asn1.x509.KeyUsage(
                    org.bouncycastle.asn1.x509.KeyUsage.keyCertSign or
                        org.bouncycastle.asn1.x509.KeyUsage.digitalSignature,
                ),
            )
        }
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(signerKey)
        return JcaX509CertificateConverter().getCertificate(builder.build(signer))
    }
}
