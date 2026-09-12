package com.kypeli.mtlspoc.ui

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.kypeli.mtlspoc.data.repository.SecurityRepository
import com.kypeli.mtlspoc.security.HardwareSecurityLevel
import dev.zacsweers.metro.Inject
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.security.cert.X509Certificate

@Inject
class MainViewModel(
    private val securityRepository: SecurityRepository,
) : ViewModel() {
    private val _uiState = MutableStateFlow<UiState>(UiState.Idle)
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    init {
        checkEnrollmentStatus()
    }

    fun checkEnrollmentStatus() {
        if (securityRepository.isEnrolled()) {
            val level = securityRepository.getSecurityLevel() ?: HardwareSecurityLevel.TEE
            _uiState.value =
                UiState.Enrolled(
                    message = "Device key is enrolled",
                    securityLevel = level,
                )
        } else {
            _uiState.value = UiState.Idle
        }
    }

    fun enroll(forceStrongBox: Boolean = true) {
        viewModelScope.launch {
            _uiState.value = UiState.Enrolling("Generating key and enrolling with backend...")
            try {
                val result = securityRepository.enroll(forceStrongBox = forceStrongBox)
                val leafCert = result.certificateChain.firstOrNull() as? X509Certificate
                _uiState.value =
                    UiState.Enrolled(
                        message = "Enrolled successfully with ${result.securityLevel}",
                        securityLevel = result.securityLevel,
                        certificateSubject = leafCert?.subjectDN?.name,
                    )
            } catch (e: Exception) {
                Log.e(TAG, "Enrollment failed", e)
                _uiState.value = UiState.Error("Enrollment failed: ${e.message ?: e.localizedMessage}")
            }
        }
    }

    fun pingProtected(caCertificatePemOrDer: ByteArray? = null) {
        viewModelScope.launch {
            _uiState.value = UiState.Authenticating("Pinging protected API over mTLS 1.3...")
            try {
                val response = securityRepository.pingProtected(caCertificatePemOrDer)
                val msg = response.message ?: "Status: ${response.status} (Client: ${response.clientIdentity})"
                _uiState.value =
                    UiState.Authenticated(
                        message = msg,
                        timestamp = response.timestamp,
                        clientIdentity = response.clientIdentity,
                    )
            } catch (e: Exception) {
                Log.e(TAG, "mTLS ping failed", e)
                _uiState.value = UiState.Error("mTLS Ping failed: ${e.message ?: e.localizedMessage}")
            }
        }
    }

    fun connect() {
        viewModelScope.launch {
            try {
                if (!securityRepository.isEnrolled()) {
                    _uiState.value = UiState.Enrolling("Device not enrolled. Enrolling hardware key...")
                    securityRepository.enroll()
                }
                _uiState.value = UiState.Authenticating("Connecting via mTLS 1.3 to /api/v1/protected/ping...")
                val response = securityRepository.pingProtected()
                val msg = response.message ?: "Status: ${response.status} (Client: ${response.clientIdentity})"
                _uiState.value =
                    UiState.Authenticated(
                        message = msg,
                        timestamp = response.timestamp,
                        clientIdentity = response.clientIdentity,
                    )
            } catch (e: Exception) {
                Log.e(TAG, "Connection failed", e)
                _uiState.value = UiState.Error("Connection failed: ${e.message ?: e.localizedMessage}")
            }
        }
    }

    /**
     * Invoked when the user denies ACCESS_LOCAL_NETWORK (or has revoked it in system
     * settings). Without that permission the OS silently drops local-network traffic,
     * so we surface an actionable error instead of attempting a doomed connection.
     */
    fun onLocalNetworkPermissionDenied() {
        _uiState.value =
            UiState.Error(
                "Local network access was denied. Grant 'Local network access' in " +
                    "Settings → Apps → mTLS PoC and try again.",
            )
    }

    private companion object {
        private const val TAG = "MainViewModel"
    }
}
