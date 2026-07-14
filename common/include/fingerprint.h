#pragma once

/**
 * fingerprint.h — Hardware fingerprinting.
 *
 * Collects stable, hard-to-spoof machine identifiers and combines them
 * into a SHA-256 fingerprint hash.
 *
 * Sources (in priority order):
 *  1. TPM Endorsement Key (EK) public key hash  — strongest anchor
 *  2. Motherboard / BIOS UUID (SMBIOS)
 *  3. CPU identifier
 *  4. Primary disk serial number
 *
 * If no TPM is available the license is marked "software-bound only".
 */

#include <optional>
#include <string>
#include <vector>

namespace license::fingerprint {

// ──────────────────────────────────────────────
// Individual component accessors
// ──────────────────────────────────────────────

/// SHA-256 of the TPM Endorsement Key public key, or nullopt if no TPM.
[[nodiscard]] std::optional<std::string> tpm_ek_hash();

/// SMBIOS system UUID (e.g. "6ba7b810-9dad-11d1-80b4-00c04fd430c8").
/// Returns empty string if unavailable.
[[nodiscard]] std::string smbios_uuid();

/// CPU identifier string (brand string + family/model/stepping hex).
[[nodiscard]] std::string cpu_id();

/// Serial number of the primary storage device, or empty if unavailable.
[[nodiscard]] std::string primary_disk_serial();

// ──────────────────────────────────────────────
// Composite fingerprint
// ──────────────────────────────────────────────

struct FingerprintResult {
    /// Hex-encoded SHA-256 of all collected components.
    std::string hash;

    /// True if TPM EK was included in the hash (hardware-bound).
    bool tpm_bound{false};

    /// Human-readable assurance level for logging / license record.
    /// "hardware" (TPM EK present) or "software" (no TPM).
    std::string assurance_level;

    /// The individual components that were hashed (for debugging).
    std::vector<std::string> components;
};

/**
 * Collect hardware fingerprint components and compute the composite hash.
 *
 * The hash is computed as:
 *   SHA-256( "LFPV1" || len32(tpm_ek) || tpm_ek
 *                     || len32(bios_uuid) || bios_uuid
 *                     || len32(cpu_id)    || cpu_id
 *                     || len32(disk_ser)  || disk_ser )
 *
 * The length-prefixed encoding prevents component boundary confusion.
 * Components that are unavailable are encoded as zero-length.
 *
 * @param use_tpm   If false, skip TPM EK even if available (testing only).
 */
[[nodiscard]] FingerprintResult compute(bool use_tpm = true);

/**
 * Verify that `expected_hash` matches the current machine's fingerprint.
 * Uses constant-time comparison.
 */
[[nodiscard]] bool verify(const std::string& expected_hash, bool use_tpm = true);

}  // namespace license::fingerprint
