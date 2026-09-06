package com.kypeli.mtlspoc.security

/**
 * Represents the security level of the hardware or environment backing
 * cryptographic key generation and storage within the Android Keystore.
 */
enum class HardwareSecurityLevel {
    /**
     * Dedicated hardware security module (HSM) with its own CPU, memory, and true random number generator,
     * providing the highest level of physical and side-channel tamper resistance (e.g. Titan M).
     */
    STRONGBOX,

    /**
     * Trusted Execution Environment (TEE) running isolated on the main processor alongside Android OS,
     * protected by hardware-enforced memory isolation (e.g. ARM TrustZone).
     */
    TEE,

    /**
     * Software-backed fallback emulation without hardware protection or isolation guarantees.
     */
    SOFTWARE,
}
