package com.kypeli.mtlspoc.data.model

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

@JsonClass(generateAdapter = true)
data class ChallengeResponse(
    @param:Json(name = "challenge") val challenge: String, // Base64 encoded nonce
    @param:Json(name = "expires_in") val expiresIn: Long? = null
)
