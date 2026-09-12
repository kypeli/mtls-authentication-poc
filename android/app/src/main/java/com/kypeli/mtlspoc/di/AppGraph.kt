package com.kypeli.mtlspoc.di

import android.content.Context
import android.provider.Settings
import com.kypeli.mtlspoc.data.repository.SecurityRepository
import com.kypeli.mtlspoc.ui.MainViewModel
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.DependencyGraph
import dev.zacsweers.metro.Provides
import dev.zacsweers.metro.SingleIn
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor

private val BASE_URL = "https://192.168.1.150"

@SingleIn(AppScope::class)
@DependencyGraph(AppScope::class)
interface AppGraph {
    val securityRepository: SecurityRepository
    val mainViewModel: MainViewModel

    @Provides
    @SingleIn(AppScope::class)
    fun provideOkHttpClient(): OkHttpClient {
        val logging =
            HttpLoggingInterceptor().apply {
                level = HttpLoggingInterceptor.Level.BODY
            }
        return OkHttpClient
            .Builder()
            .addInterceptor(logging)
            .build()
    }

    @Provides
    @EnrollmentBaseUrl
    fun provideEnrollmentBaseUrl(): String = "$BASE_URL:8080"

    @Provides
    @ProtectedBaseUrl
    fun provideProtectedBaseUrl(): String = "$BASE_URL:8443"

    @Provides
    @DeviceId
    fun provideDeviceId(context: Context): String =
        Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
            ?: "android-unknown-device"

    @DependencyGraph.Factory
    fun interface Factory {
        fun create(
            @Provides context: Context,
        ): AppGraph
    }
}
