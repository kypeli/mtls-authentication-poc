package com.kypeli.mtlspoc.data.api

import com.kypeli.mtlspoc.data.model.ChallengeResponse
import com.kypeli.mtlspoc.data.model.EnrollRequest
import com.kypeli.mtlspoc.data.model.EnrollResponse
import com.kypeli.mtlspoc.di.EnrollmentBaseUrl
import com.squareup.moshi.Moshi
import dev.zacsweers.metro.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException

@Inject
class EnrollmentApi(
    @param:EnrollmentBaseUrl private val baseUrl: String,
    private val okHttpClient: OkHttpClient = OkHttpClient(),
) {
    private val moshi = Moshi.Builder().build()

    private val challengeAdapter = moshi.adapter(ChallengeResponse::class.java)
    private val enrollRequestAdapter = moshi.adapter(EnrollRequest::class.java)
    private val enrollResponseAdapter = moshi.adapter(EnrollResponse::class.java)

    suspend fun getChallenge(): ChallengeResponse =
        withContext(Dispatchers.IO) {
            val request =
                Request
                    .Builder()
                    .url("$baseUrl/api/v1/enroll/challenge")
                    .get()
                    .build()

            okHttpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    throw IOException("Failed to get challenge: HTTP ${response.code} ${response.message}")
                }
                val body = response.body.string()
                challengeAdapter.fromJson(body) ?: throw IOException("Failed to parse challenge response")
            }
        }

    suspend fun enroll(requestPayload: EnrollRequest): EnrollResponse =
        withContext(Dispatchers.IO) {
            val json = enrollRequestAdapter.toJson(requestPayload)
            val requestBody = json.toRequestBody("application/json; charset=utf-8".toMediaType())

            val request =
                Request
                    .Builder()
                    .url("$baseUrl/api/v1/enroll")
                    .post(requestBody)
                    .build()

            okHttpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    val errorBody = response.body.string()
                    throw IOException("Enrollment failed: HTTP ${response.code} ${response.message}: $errorBody")
                }
                val body = response.body.string()
                enrollResponseAdapter.fromJson(body) ?: throw IOException("Failed to parse enroll response")
            }
        }
}
