package com.kypeli.mtlspoc.data.model

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class EnrollRequest(
    @param:Json(name = "device_id") val deviceId: String,
    @param:Json(name = "csr") val csr: String, // Base64 encoded DER CSR
    @param:Json(name = "attestation_chain") val attestationChain: List<String> // List of Base64 encoded DER certs
)

@JsonClass(generateAdapter = true)
data class EnrollResponse(
    @param:Json(name = "client_certificate") val clientCertificate: String, // PEM or Base64 DER
    @param:Json(name = "ca_certificate") val caCertificate: String? = null, // PEM or Base64 DER
    @param:Json(name = "certificate_chain") val certificateChain: List<String>? = null // Optional full chain in Base64 DER / PEM
)
