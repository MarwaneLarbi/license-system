#pragma once

/**
 * license_client.h — Public API for liblicenseclient.
 *
 * ZERO CODE CHANGES REQUIRED for deployment.
 *
 * Server public keys are loaded at runtime from a JSON config file
 * (produced by `license-server init-keys --pub-out server_pubkeys.json`).
 * There are no compiled-in key constants; key rotation is purely a
 * file-distribution and CLI operation.
 *
 * Typical embedded usage:
 *
 *   #include "license_client.h"
 *
 *   int main() {
 *       auto keys = license::client::load_server_keys("server_pubkeys.json");
 *       auto r    = license::client::verify_at_startup("myapp-pro", keys);
 *       if (!r.valid) { std::cerr << r.error; return 1; }
 *   }
 *
 * Key rotation: run `license-server init-keys --pub-out new_pubkeys.json`,
 * distribute the new JSON file to customers, re-issue licenses.
 * No rebuild of the client binary is needed.
 */

#include <cstdint>
#include <string>
#include <vector>

namespace license::client {

// ──────────────────────────────────────────────
// Runtime server key configuration
// ──────────────────────────────────────────────

/**
 * Runtime-loaded server public keys.
 * Populated by load_server_keys() from a JSON file written by
 * `license-server init-keys --pub-out <path>`.
 */
struct ServerKeys {
    std::vector<uint8_t> ed25519_pub;  ///< 32-byte Ed25519 public key (signature verification)
    std::vector<uint8_t> x25519_pub;   ///< 32-byte X25519 public key (request encryption)
};

/**
 * Load server public keys from a JSON config file.
 *
 * The file is produced by:
 *   license-server init-keys --keystore <path> --pub-out server_pubkeys.json
 *
 * Expected JSON format:
 *   {
 *     "version": "1",
 *     "server_x25519_pub":  "<base64>",
 *     "server_ed25519_pub": "<base64>"
 *   }
 *
 * @param config_path  Path to server_pubkeys.json.
 * @throws std::runtime_error if the file is missing, malformed, or keys
 *         are not the expected 32 bytes.
 */
[[nodiscard]] ServerKeys load_server_keys(const std::string& config_path);

// ──────────────────────────────────────────────
// Result types
// ──────────────────────────────────────────────

struct GenerateRequestResult {
    bool success{false};
    std::string blob_b64;  ///< base64 hybrid-encrypted request blob
    std::string fingerprint_hash;
    std::string fingerprint_assurance;
    std::string error;
};

struct ActivateResult {
    bool success{false};
    std::string license_id;
    std::string product_id;
    std::string error;
};

struct VerifyResult {
    bool valid{false};
    std::string license_id;
    std::string product_id;
    std::string assurance_level;  ///< "hardware" | "software"
    int64_t expires_at{};         ///< Unix timestamp; 0 = no expiry
    int64_t issued_at{};
    std::vector<std::string> features;
    std::string error;
};

// ──────────────────────────────────────────────
// API
// ──────────────────────────────────────────────

/**
 * Generate a license request blob to send to the vendor.
 *
 * Collects hardware fingerprint, generates/loads the device keypair,
 * and produces a hybrid-encrypted JSON blob addressed to the server's
 * X25519 key.
 *
 * @param product_id      Product identifier (must match vendor's expectation).
 * @param customer_hint   Optional human-readable name / email for vendor reference.
 * @param keys            Server public keys loaded from server_pubkeys.json.
 */
[[nodiscard]] GenerateRequestResult generate_request(const std::string& product_id,
                                                      const std::string& customer_hint,
                                                      const ServerKeys& keys);

/**
 * Activate a license token received from the vendor.
 *
 * Verifies the Ed25519 signature against keys.ed25519_pub,
 * checks the hardware fingerprint, checks expiry, and seals the
 * validated license into TPM-protected local storage.
 *
 * @param token_b64  The signed license token from license-server.
 * @param keys       Server public keys loaded from server_pubkeys.json.
 */
[[nodiscard]] ActivateResult activate(const std::string& token_b64, const ServerKeys& keys);

/**
 * Verify the locally stored license at startup.
 *
 * Unseals the license from TPM-protected storage, then re-verifies
 * the Ed25519 signature, hardware fingerprint, and expiry.
 *
 * @param product_id  The product identifier to verify against.
 * @param keys        Server public keys loaded from server_pubkeys.json.
 */
[[nodiscard]] VerifyResult verify_at_startup(const std::string& product_id,
                                              const ServerKeys& keys);

/**
 * Remove the locally stored license (deactivate).
 * Overwrites the sealed blob with random bytes before deletion.
 * Returns true on success.
 */
bool deactivate(const std::string& product_id);

}  // namespace license::client
