package com.kypeli.mtlspoc.security

import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.operator.ContentSigner
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.security.PrivateKey
import java.security.Signature

/**
 * Custom ContentSigner implementation that delegates signing to AndroidKeyStore
 * without extracting or touching private key bytes.
 */
class AndroidKeystoreSigner(
    private val privateKey: PrivateKey,
    private val algorithm: String = "SHA256withECDSA"
) : ContentSigner {

    private val outputStream = ByteArrayOutputStream()
    private val sigAlgId = AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256)

    override fun getAlgorithmIdentifier(): AlgorithmIdentifier {
        return sigAlgId
    }

    override fun getOutputStream(): OutputStream {
        return outputStream
    }

    override fun getSignature(): ByteArray {
        val sig = Signature.getInstance(algorithm)
        sig.initSign(privateKey)
        sig.update(outputStream.toByteArray())
        return sig.sign()
    }
}
