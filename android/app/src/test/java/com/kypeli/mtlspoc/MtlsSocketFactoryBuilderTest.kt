package com.kypeli.mtlspoc

import com.kypeli.mtlspoc.security.MtlsSocketFactoryBuilder
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertNotNull
import org.junit.Test
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.util.Date

class MtlsSocketFactoryBuilderTest {

    @Test
    fun testBuildMtlsSocketFactory() {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val keyPair = kpg.generateKeyPair()

        // Generate self-signed certificate for test keystore
        val subject = X500Name("CN=TestRootCA")
        val notBefore = Date(System.currentTimeMillis() - 1000 * 60)
        val notAfter = Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24)
        val serialNumber = BigInteger(64, SecureRandom())
        val subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)

        val certBuilder = X509v3CertificateBuilder(
            subject,
            serialNumber,
            notBefore,
            notAfter,
            subject,
            subPubKeyInfo
        )
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.private)
        val certHolder = certBuilder.build(signer)
        val x509Cert = JcaX509CertificateConverter().getCertificate(certHolder)

        val alias = "test_alias"
        val testKeyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setKeyEntry(alias, keyPair.private, null, arrayOf(x509Cert))
        }

        val caCertBytes = x509Cert.encoded
        val builder = MtlsSocketFactoryBuilder(testKeyStore, alias)
        val sslConfig = builder.build(ByteArrayInputStream(caCertBytes))

        assertNotNull(sslConfig.sslSocketFactory)
        assertNotNull(sslConfig.trustManager)
        assertNotNull(sslConfig.trustManager.acceptedIssuers)
    }
}
