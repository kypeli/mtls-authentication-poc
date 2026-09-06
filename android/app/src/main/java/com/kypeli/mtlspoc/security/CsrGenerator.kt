package com.kypeli.mtlspoc.security

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

object CsrGenerator {

    /**
     * Generates a DER-encoded PKCS#10 Certificate Signing Request (CSR)
     * using the hardware-backed private key and its corresponding public key.
     */
    fun generateCsrDer(
        subjectCommonName: String,
        privateKey: PrivateKey,
        publicKey: PublicKey
    ): ByteArray {
        val subject = X500Name("CN=$subjectCommonName")
        val builder = JcaPKCS10CertificationRequestBuilder(subject, publicKey)
        val signer = AndroidKeystoreSigner(privateKey)
        val csr: PKCS10CertificationRequest = builder.build(signer)
        return csr.encoded
    }

    /**
     * Convenience method taking a KeyPair
     */
    fun generateCsrDer(
        subjectCommonName: String,
        keyPair: KeyPair
    ): ByteArray {
        return generateCsrDer(subjectCommonName, keyPair.private, keyPair.public)
    }
}
