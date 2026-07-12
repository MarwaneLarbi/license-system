#pragma once

/**
 * crypto.h — Cryptographic primitives layer.
 *
 * All crypto is done through OpenSSL 3.x EVP API only.
 * No deprecated low-level calls. No hardcoded secrets.
 *
 * Key separation:
 *   - X25519  : ephemeral ECDH for hybrid encryption (request blobs)
 *   - Ed25519 : signing / verification (license tokens)
 *   - AES-256-GCM : authenticated symmetric encryption
 *   - HKDF-SHA256  : symmetric key derivation
 */

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace license::crypto {

// ──────────────────────────────────────────────
// Type aliases
// ──────────────────────────────────────────────
using Bytes = std::vector<uint8_t>;

// ──────────────────────────────────────────────
// Base64 utilities
// ──────────────────────────────────────────────

/// Encode raw bytes to standard base64 (no line breaks).
[[nodiscard]] std::string base64_encode(std::span<const uint8_t> data);

/// Decode base64 to raw bytes.  Throws std::runtime_error on invalid input.
[[nodiscard]] Bytes base64_decode(std::string_view b64);

// ──────────────────────────────────────────────
// Random bytes
// ──────────────────────────────────────────────

/// Fill `out` with `n` cryptographically secure random bytes.
void random_bytes(uint8_t* out, std::size_t n);
[[nodiscard]] Bytes random_bytes(std::size_t n);

// ──────────────────────────────────────────────
// Constant-time comparison (avoids timing oracles)
// ──────────────────────────────────────────────

/// Returns true iff a == b, evaluated in constant time w.r.t. content.
[[nodiscard]] bool ct_equal(std::span<const uint8_t> a,
                            std::span<const uint8_t> b);

// ──────────────────────────────────────────────
// SHA-256
// ──────────────────────────────────────────────

[[nodiscard]] Bytes sha256(std::span<const uint8_t> data);
[[nodiscard]] Bytes sha256(std::string_view data);

// ──────────────────────────────────────────────
// HKDF-SHA256
// ──────────────────────────────────────────────

/**
 * HKDF-SHA256 key derivation.
 *
 * @param ikm   Input key material.
 * @param salt  Optional salt (can be empty).
 * @param info  Context / application label.
 * @param len   Output length in bytes (≤ 255 * 32).
 */
[[nodiscard]] Bytes hkdf_sha256(std::span<const uint8_t> ikm,
                                std::span<const uint8_t> salt,
                                std::span<const uint8_t> info,
                                std::size_t              len);

// ──────────────────────────────────────────────
// AES-256-GCM
// ──────────────────────────────────────────────

struct AeadParams {
    static constexpr std::size_t KEY_LEN  = 32; // 256 bits
    static constexpr std::size_t NONCE_LEN = 12; // 96 bits (recommended for GCM)
    static constexpr std::size_t TAG_LEN  = 16; // 128-bit authentication tag
};

/**
 * Encrypt plaintext with AES-256-GCM.
 *
 * Returns: nonce (12 B) || ciphertext || tag (16 B)
 *
 * @param key   32-byte encryption key.
 * @param aad   Additional authenticated data (not encrypted, but authenticated).
 * @param plain Plaintext to encrypt.
 */
[[nodiscard]] Bytes aes256gcm_encrypt(std::span<const uint8_t> key,
                                      std::span<const uint8_t> aad,
                                      std::span<const uint8_t> plain);

/**
 * Decrypt and verify AES-256-GCM ciphertext.
 *
 * Input format: nonce (12 B) || ciphertext || tag (16 B)
 * Throws std::runtime_error on authentication failure.
 */
[[nodiscard]] Bytes aes256gcm_decrypt(std::span<const uint8_t> key,
                                      std::span<const uint8_t> aad,
                                      std::span<const uint8_t> ciphertext);

// ──────────────────────────────────────────────
// X25519 key exchange
// ──────────────────────────────────────────────

struct X25519KeyPair {
    Bytes pub;   // 32 bytes — raw public key
    Bytes priv;  // 32 bytes — raw private key (SECRET — never log)
};

[[nodiscard]] X25519KeyPair x25519_generate_keypair();

/**
 * ECDH: shared secret from our private key and peer's public key.
 * Returns raw 32-byte X25519 output (feed into HKDF before using).
 */
[[nodiscard]] Bytes x25519_exchange(std::span<const uint8_t> our_priv,
                                    std::span<const uint8_t> peer_pub);

// ──────────────────────────────────────────────
// Ed25519 signing
// ──────────────────────────────────────────────

struct Ed25519KeyPair {
    Bytes pub;   // 32 bytes
    Bytes priv;  // 64 bytes (seed || pub) — SECRET — never log
};

[[nodiscard]] Ed25519KeyPair ed25519_generate_keypair();

/**
 * Sign `message` with Ed25519 private key.
 * Returns 64-byte detached signature.
 */
[[nodiscard]] Bytes ed25519_sign(std::span<const uint8_t> priv_key,
                                 std::span<const uint8_t> message);

/**
 * Verify Ed25519 signature.
 * Returns true iff signature is valid. Evaluated in constant time.
 */
[[nodiscard]] bool ed25519_verify(std::span<const uint8_t> pub_key,
                                  std::span<const uint8_t> message,
                                  std::span<const uint8_t> signature);

// ──────────────────────────────────────────────
// Hybrid encryption (X25519 + HKDF + AES-256-GCM)
// ──────────────────────────────────────────────

/**
 * Encrypt `plaintext` to `recipient_pub` using hybrid encryption.
 *
 * Wire format (all base64-encoded in the outer JSON, raw here):
 *   ephemeral_pub (32 B) || nonce (12 B) || ciphertext || tag (16 B)
 *
 * SECURITY NOTE: The recipient's private key must be kept secret.
 * If it is ever compromised, all past blobs encrypted to this key can be
 * decrypted.  Key rotation: generate a new server keypair, publish the new
 * public key in a new client build, and re-issue affected licenses.
 *
 * @param recipient_pub  32-byte X25519 public key of the recipient.
 * @param aad            Additional authenticated data (e.g. product_id + version).
 * @param plaintext      Data to encrypt.
 */
[[nodiscard]] Bytes hybrid_encrypt(std::span<const uint8_t> recipient_pub,
                                   std::span<const uint8_t> aad,
                                   std::span<const uint8_t> plaintext);

/**
 * Decrypt a hybrid-encrypted blob.
 *
 * @param recipient_priv 32-byte X25519 private key of the recipient. SECRET.
 * @param aad            Must match the AAD used during encryption.
 * @param ciphertext     Raw bytes from hybrid_encrypt().
 */
[[nodiscard]] Bytes hybrid_decrypt(std::span<const uint8_t> recipient_priv,
                                   std::span<const uint8_t> aad,
                                   std::span<const uint8_t> ciphertext);

} // namespace license::crypto
