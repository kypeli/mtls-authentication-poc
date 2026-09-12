package com.kypeli.mtlspoc.di

import android.content.Context
import android.content.pm.ApplicationInfo
import android.provider.Settings
import com.kypeli.mtlspoc.BuildConfig
import com.kypeli.mtlspoc.data.repository.SecurityRepository
import com.kypeli.mtlspoc.ui.MainViewModel
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.DependencyGraph
import dev.zacsweers.metro.Provides
import dev.zacsweers.metro.SingleIn
import okhttp3.OkHttpClient

@SingleIn(AppScope::class)
@DependencyGraph(AppScope::class)
interface AppGraph {
    val securityRepository: SecurityRepository
    val mainViewModel: MainViewModel

    @Provides
    @SingleIn(AppScope::class)
    fun provideOkHttpClient(
        @DebugLoggingEnabled debugLoggingEnabled: Boolean,
    ): OkHttpClient {
        val builder = OkHttpClient.Builder()
        if (debugLoggingEnabled) {
            val logging =
                okhttp3.logging.HttpLoggingInterceptor().apply {
                    level = okhttp3.logging.HttpLoggingInterceptor.Level.BODY
                }
            builder.addInterceptor(logging)
        }
        return builder.build()
    }

    @Provides
    @DebugLoggingEnabled
    fun provideDebugLoggingEnabled(context: Context): Boolean =
        (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

    @Provides
    @EnrollmentBaseUrl
    fun provideEnrollmentBaseUrl(): String = "${BuildConfig.BACKEND_HOST}:8080"

    @Provides
    @ProtectedBaseUrl
    fun provideProtectedBaseUrl(): String = "${BuildConfig.BACKEND_HOST}:8443"

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
