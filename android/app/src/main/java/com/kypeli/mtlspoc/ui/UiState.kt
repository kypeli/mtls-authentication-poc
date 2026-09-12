package com.kypeli.mtlspoc.ui

import com.kypeli.mtlspoc.security.HardwareSecurityLevel

sealed interface UiState {
    data object Idle : UiState

    data class Enrolling(
        val message: String = "Enrolling key in hardware...",
    ) : UiState

    data class Enrolled(
        val message: String = "Enrollment successful",
        val securityLevel: HardwareSecurityLevel,
        val certificateSubject: String? = null,
    ) : UiState

    data class Authenticating(
        val message: String = "Connecting via mTLS 1.3...",
    ) : UiState

    data class Authenticated(
        val message: String,
        val timestamp: Long? = null,
        val clientIdentity: String? = null,
    ) : UiState

    data class Error(
        val error: String,
    ) : UiState
}
