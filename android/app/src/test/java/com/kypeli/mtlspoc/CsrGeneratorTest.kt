package com.kypeli.mtlspoc

import com.kypeli.mtlspoc.security.CsrGenerator
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec

class CsrGeneratorTest {

    @Test
    fun testCsrGenerationAndVerification() {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val keyPair = kpg.generateKeyPair()

        val deviceId = "device-test-12345"
        val csrDer = CsrGenerator.generateCsrDer(deviceId, keyPair)

        assertNotNull(csrDer)
        assertTrue(csrDer.isNotEmpty())

        val csr = PKCS10CertificationRequest(csrDer)
        assertEquals(X500Name("CN=$deviceId"), csr.subject)

        val verifierProvider = JcaContentVerifierProviderBuilder().build(keyPair.public)
        val isSignatureValid = csr.isSignatureValid(verifierProvider)
        assertTrue("CSR signature should be valid", isSignatureValid)
    }
}
