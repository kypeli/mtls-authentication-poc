package com.kypeli.mtlspoc.data.model

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class ProtectedResponse(
    @param:Json(name = "status") val status: String,
    @param:Json(name = "message") val message: String? = null,
    @param:Json(name = "client_identity") val clientIdentity: String? = null,
    @param:Json(name = "timestamp") val timestamp: Long? = null
)
