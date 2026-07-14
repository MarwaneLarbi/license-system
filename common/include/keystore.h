#pragma once

/**
 * keystore.h — Encrypted server-side key store.
 *
 * The keystore file stores the server's long-term private keys encrypted with:
 *   1. Argon2id KDF (passphrase -> master key)
 *   2. AES-256-GCM (master key -> ciphertext)
 *   3. Optionally additionally sealed by TPM (hardware server only)
 *
 * File format (JSON):
 * {
 *   "version": 1,
 *   "argon2id": { "t_cost": N, "m_cost": N, "parallelism": N, "salt_b64": "..." },
 *   "tpm_sealed": true|false,
 *   "payload_b64": "..."   // AES-256-GCM(nonce||ct||tag) of inner_json
 * }
 *
 * inner_json:
 * {
 *   "server_x25519_priv_b64": "...",  // 32-byte X25519 private key
 *   "server_x25519_pub_b64":  "...",  // 32-byte X25519 public key
 *   "server_ed25519_priv_b64": "...", // 64-byte Ed25519 private key
 *   "server_ed25519_pub_b64":  "...", // 32-byte Ed25519 public key
 *   "created_at": N
 * }
 *
 * SECURITY NOTES:
 * - Private keys are NEVER written to disk in plaintext.
 * - The passphrase is the only secret input; do not log it or derive it
 *   from machine state accessible to unprivileged processes.
 * - Key rotation: generate a new keystore with generate_keystore(), publish
 *   the new server_ed25519_pub and server_x25519_pub in the next client
 *   build, and re-sign affected licenses with sign_license().
 */

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace license::tpm {
class ITpmProvider;
}

namespace license::keystore {

using Bytes = std::vector<uint8_t>;

// ──────────────────────────────────────────────
// Argon2id parameters (server-side defaults)
// ──────────────────────────────────────────────
struct Argon2Params {
    uint32_t t_cost = 3;         // iterations
    uint32_t m_cost = 1u << 17;  // 128 MiB
    uint32_t parallelism = 4;
};

// ──────────────────────────────────────────────
// Server keys (in memory only — never serialise raw)
// ──────────────────────────────────────────────
struct ServerKeys {
    Bytes x25519_priv;   // 32 B, SECRET
    Bytes x25519_pub;    // 32 B
    Bytes ed25519_priv;  // 64 B, SECRET
    Bytes ed25519_pub;   // 32 B

    /// Wipe all key material from memory.
    ~ServerKeys();
};

// ──────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────

/**
 * Generate a new set of server keys and write an encrypted keystore file.
 *
 * @param path        Output file path.
 * @param passphrase  Argon2id-stretched to derive the encryption key. SECRET.
 * @param params      Argon2id cost parameters.
 * @param tpm         Optional TPM provider for additional TPM-sealing.
 *
 * @returns The newly generated public keys (safe to log / embed in client).
 */
struct PublicKeys {
    std::string x25519_pub_b64;
    std::string ed25519_pub_b64;
};

[[nodiscard]] PublicKeys generate_keystore(const std::string& path, const std::string& passphrase,
                                           const Argon2Params& params = {},
                                           license::tpm::ITpmProvider* tpm = nullptr);

/**
 * Load and decrypt a keystore file.
 *
 * @param path        Keystore file path.
 * @param passphrase  Decryption passphrase. SECRET.
 * @param tpm         Optional TPM provider (required if keystore was TPM-sealed).
 *
 * Throws std::runtime_error on wrong passphrase, corrupt file, or
 * failed TPM unseal.
 */
[[nodiscard]] std::unique_ptr<ServerKeys> load_keystore(const std::string& path,
                                                        const std::string& passphrase,
                                                        license::tpm::ITpmProvider* tpm = nullptr);

}  // namespace license::keystore
