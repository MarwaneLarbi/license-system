#pragma once

/**
 * license.h — License record and token format.
 *
 * License token wire format (compact, base64-encoded):
 *   JSON payload (UTF-8) || "." || base64(Ed25519 signature, 64 B)
 *
 * The payload is the canonical JSON with no extra whitespace, sorted keys.
 */

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace license {

// ──────────────────────────────────────────────
// Feature flags
// ──────────────────────────────────────────────
using FeatureList = std::vector<std::string>;

// ──────────────────────────────────────────────
// Request payload (customer -> vendor)
// ──────────────────────────────────────────────

struct LicenseRequest {
    std::string product_id;       // e.g. "myapp-pro"
    std::string customer_hint;    // name / email (not verified, for human ref)
    std::string fingerprint_hash; // hex SHA-256 of hardware fingerprint
    std::string fingerprint_assurance; // "hardware" | "software"
    std::string device_pubkey_b64; // base64 Ed25519 device public key
    int64_t     timestamp{};      // Unix seconds UTC
    std::string nonce;            // 16 random bytes, base64-encoded
};

/// Serialise a request to JSON string.
[[nodiscard]] std::string to_json(const LicenseRequest& req);

/// Parse JSON back into a LicenseRequest. Throws on malformed input.
[[nodiscard]] LicenseRequest request_from_json(const std::string& json);

// ──────────────────────────────────────────────
// License record (vendor -> customer)
// ──────────────────────────────────────────────

struct LicenseRecord {
    std::string  license_id;          // UUID
    std::string  product_id;
    std::string  fingerprint_hash;     // hex SHA-256 (must match activating machine)
    std::string  fingerprint_assurance; // "hardware" | "software"
    FeatureList  features;
    int64_t      issued_at{};         // Unix seconds UTC
    int64_t      expires_at{};        // Unix seconds UTC (0 = no expiry)
    uint32_t     max_activations{1};
};

/// Serialise a record to canonical JSON (sorted keys, no whitespace).
[[nodiscard]] std::string to_json(const LicenseRecord& rec);

/// Parse JSON back into a LicenseRecord. Throws on malformed input.
[[nodiscard]] LicenseRecord record_from_json(const std::string& json);

// ──────────────────────────────────────────────
// Signed license token
// ──────────────────────────────────────────────

/**
 * Build a signed license token.
 *
 * Format: base64(payload_json) "." base64(ed25519_sig)
 *
 * @param record       The license record.
 * @param ed25519_priv 64-byte Ed25519 private key. SECRET — never logged.
 */
[[nodiscard]] std::string sign_license(const LicenseRecord&     record,
                                       std::vector<uint8_t>     ed25519_priv);

struct VerifyResult {
    bool          valid{false};
    LicenseRecord record;
    std::string   error;   // non-empty on failure
};

/**
 * Verify a signed license token.
 *
 * Checks:
 *  1. Signature valid (Ed25519, constant-time).
 *  2. Fingerprint matches current machine.
 *  3. License not expired.
 *
 * SECURITY NOTE: ed25519_pub is compiled into the client binary.
 * If this key is ever compromised, an attacker could forge valid licenses.
 * Mitigation: ship a key rotation mechanism — new client builds embed the
 * new public key, and a "migration token" signed by BOTH old and new keys
 * can be issued for a brief transition window.
 *
 * @param token        Signed token string from sign_license().
 * @param ed25519_pub  32-byte Ed25519 public key (compiled-in).
 */
[[nodiscard]] VerifyResult verify_license(const std::string&       token,
                                          std::vector<uint8_t>     ed25519_pub);

// ──────────────────────────────────────────────
// Anti-replay helpers (server-side)
// ──────────────────────────────────────────────

/**
 * Check that the request timestamp is within an acceptable window.
 * @param req_timestamp   Unix seconds from the request.
 * @param max_age_seconds Maximum allowed age (default 24h).
 */
[[nodiscard]] bool timestamp_is_fresh(int64_t req_timestamp,
                                      int64_t max_age_seconds = 86400);

/// Generate a new RFC-4122 v4 UUID string.
[[nodiscard]] std::string generate_uuid();

} // namespace license
