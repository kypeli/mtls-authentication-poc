package com.kypeli.mtlspoc.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.kypeli.mtlspoc.data.repository.SecurityRepository
import com.kypeli.mtlspoc.security.HardwareSecurityLevel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.security.cert.X509Certificate

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
                    )
            } catch (e: Exception) {
                _uiState.value = UiState.Error("mTLS Ping failed: ${e.message ?: e.localizedMessage}")
            }
        }
    }
}
