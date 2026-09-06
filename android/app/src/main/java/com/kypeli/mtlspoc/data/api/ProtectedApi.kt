package com.kypeli.mtlspoc.data.api

import com.kypeli.mtlspoc.data.model.ProtectedResponse
import com.squareup.moshi.Moshi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.IOException

class ProtectedApi(
    private val baseUrl: String,
    private val mtlsClient: OkHttpClient
) {
    private val moshi = Moshi.Builder().build()

    private val protectedResponseAdapter = moshi.adapter(ProtectedResponse::class.java)

    suspend fun ping(): ProtectedResponse = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url("$baseUrl/api/v1/protected/ping")
            .get()
            .build()

        mtlsClient.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                val errorBody = response.body?.string()
                throw IOException("Protected ping failed: HTTP ${response.code} ${response.message}: $errorBody")
            }
            val body = response.body?.string() ?: throw IOException("Empty response body")
            protectedResponseAdapter.fromJson(body) ?: throw IOException("Failed to parse ping response")
        }
    }
}
