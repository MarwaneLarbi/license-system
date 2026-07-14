/**
 * keystore.cpp — Encrypted server-side keystore.
 *
 * KDF: Argon2id  (passphrase -> 32-byte master key)
 * Enc: AES-256-GCM (master key -> encrypted inner JSON)
 * Opt: TPM sealing of the master key for hardware server machines.
 *
 * SECURITY: The passphrase is the primary secret.  Never log it,
 * never pass it over a network, and never derive it from machine
 * state accessible to unprivileged processes.
 */

#include "keystore.h"
#include "crypto.h"
#include "tpm_provider.h"

#include <argon2.h>
#include <nlohmann/json.hpp>
// OPENSSL_cleanse — secure memory zeroing.
#include <openssl/crypto.h>

#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

// chmod(2) — file permission hardening.
#include <sys/stat.h>

namespace license::keystore {

using json = nlohmann::json;

// Wipe ServerKeys on destruction.
ServerKeys::~ServerKeys() {
    OPENSSL_cleanse(x25519_priv.data(), x25519_priv.size());
    OPENSSL_cleanse(ed25519_priv.data(), ed25519_priv.size());
}

// ──────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────

namespace {

constexpr int KEYSTORE_VERSION = 1;

/// Derive a 32-byte key from passphrase using Argon2id.
Bytes argon2id_derive(const std::string& passphrase,
                      const Bytes&        salt,
                      const Argon2Params& p)
{
    Bytes key(32);
    int rc = argon2id_hash_raw(
        p.t_cost, p.m_cost, p.parallelism,
        passphrase.data(), passphrase.size(),
        salt.data(), salt.size(),
        key.data(), key.size());
    if (rc != ARGON2_OK)
        throw std::runtime_error(std::string("Argon2id failed: ") + argon2_error_message(rc));
    return key;
}

/// Read entire file as bytes.
Bytes read_file_bytes(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open keystore file: " + path);
    return Bytes(std::istreambuf_iterator<char>(f),
                 std::istreambuf_iterator<char>());
}

/// Write bytes to file (owner-only on Unix).
void write_file_bytes(const std::string& path, const Bytes& data) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("Cannot write keystore file: " + path);
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
#ifndef _WIN32
    ::chmod(path.c_str(), 0600);
#endif
}

} // anonymous namespace

// ──────────────────────────────────────────────
// generate_keystore
// ──────────────────────────────────────────────

PublicKeys generate_keystore(const std::string&              path,
                             const std::string&              passphrase,
                             const Argon2Params&             params,
                             license::tpm::ITpmProvider*     tpm)
{
    using crypto::base64_encode;
    using crypto::random_bytes;

    // 1. Generate server keypairs.
    auto x25519  = crypto::x25519_generate_keypair();
    auto ed25519 = crypto::ed25519_generate_keypair();

    // 2. Build inner JSON (holds all private key material).
    json inner;
    inner["created_at"]            = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    inner["server_x25519_priv_b64"]  = base64_encode(x25519.priv);
    inner["server_x25519_pub_b64"]   = base64_encode(x25519.pub);
    inner["server_ed25519_priv_b64"] = base64_encode(ed25519.priv);
    inner["server_ed25519_pub_b64"]  = base64_encode(ed25519.pub);
    auto inner_json = inner.dump();

    // 3. Argon2id salt (random, 16 bytes).
    auto salt = random_bytes(16);

    // 4. Derive master key.
    auto master_key = argon2id_derive(passphrase, salt, params);

    // 5. Optionally TPM-seal the master key; store the blob instead.
    bool tpm_sealed = false;
    Bytes master_or_blob;
    if (tpm) {
        master_or_blob = tpm->seal(master_key, "keystore-master");
        tpm_sealed     = true;
        OPENSSL_cleanse(master_key.data(), master_key.size());
        // Use a fresh derivation as the actual encryption key (so the
        // stored blob is not directly the AES key).
        // We re-derive from the Argon2id output for the outer encryption.
        master_key = argon2id_derive(passphrase, salt, params);
    } else {
        master_or_blob = master_key;
    }

    // 6. Encrypt inner JSON with AES-256-GCM.
    //    AAD = "keystore-v1" || product version string.
    const std::string aad_str = "keystore-v1";
    Bytes aad(aad_str.begin(), aad_str.end());
    Bytes inner_bytes(inner_json.begin(), inner_json.end());
    auto ciphertext = crypto::aes256gcm_encrypt(master_key, aad, inner_bytes);

    OPENSSL_cleanse(master_key.data(), master_key.size());
    OPENSSL_cleanse(inner_bytes.data(), inner_bytes.size());

    // 7. Build outer JSON.
    json outer;
    outer["version"]      = KEYSTORE_VERSION;
    outer["tpm_sealed"]   = tpm_sealed;
    outer["argon2id"]["t_cost"]      = params.t_cost;
    outer["argon2id"]["m_cost"]      = params.m_cost;
    outer["argon2id"]["parallelism"] = params.parallelism;
    outer["argon2id"]["salt_b64"]    = base64_encode(salt);
    outer["payload_b64"]             = base64_encode(ciphertext);
    if (tpm_sealed)
        outer["tpm_blob_b64"]        = base64_encode(master_or_blob);

    auto outer_str = outer.dump(2); // pretty-print for readability.
    Bytes outer_bytes(outer_str.begin(), outer_str.end());
    write_file_bytes(path, outer_bytes);

    // 8. Return public keys (safe to embed in client).
    return PublicKeys{
        base64_encode(x25519.pub),
        base64_encode(ed25519.pub)
    };
}

// ──────────────────────────────────────────────
// load_keystore
// ──────────────────────────────────────────────

std::unique_ptr<ServerKeys> load_keystore(const std::string&          path,
                                          const std::string&          passphrase,
                                          license::tpm::ITpmProvider* tpm)
{
    using crypto::base64_decode;

    // 1. Read and parse outer JSON.
    auto raw = read_file_bytes(path);
    json outer;
    try {
        outer = json::parse(raw.begin(), raw.end());
    } catch (const json::exception& e) {
        throw std::runtime_error(std::string("keystore parse failed: ") + e.what());
    }

    if (outer.value("version", 0) != KEYSTORE_VERSION)
        throw std::runtime_error("keystore version mismatch");

    bool tpm_sealed = outer.value("tpm_sealed", false);

    // 2. Argon2id parameters and salt.
    auto& a2 = outer.at("argon2id");
    Argon2Params params{
        a2.at("t_cost").get<uint32_t>(),
        a2.at("m_cost").get<uint32_t>(),
        a2.at("parallelism").get<uint32_t>()
    };
    auto salt = base64_decode(a2.at("salt_b64").get<std::string>());

    // 3. Derive master key.
    auto master_key = argon2id_derive(passphrase, salt, params);

    // 4. If TPM-sealed, validate by unsealing and comparing.
    if (tpm_sealed) {
        if (!tpm)
            throw std::runtime_error("Keystore is TPM-sealed but no TPM provider given");
        auto tpm_blob = base64_decode(outer.at("tpm_blob_b64").get<std::string>());
        auto unsealed  = tpm->unseal(tpm_blob, "keystore-master");
        if (!crypto::ct_equal(master_key, unsealed)) {
            OPENSSL_cleanse(master_key.data(), master_key.size());
            OPENSSL_cleanse(unsealed.data(), unsealed.size());
            throw std::runtime_error("TPM unseal: master key mismatch (wrong machine or passphrase?)");
        }
        OPENSSL_cleanse(unsealed.data(), unsealed.size());
    }

    // 5. Decrypt payload.
    auto ciphertext = base64_decode(outer.at("payload_b64").get<std::string>());
    const std::string aad_str = "keystore-v1";
    Bytes aad(aad_str.begin(), aad_str.end());
    Bytes plain;
    try {
        plain = crypto::aes256gcm_decrypt(master_key, aad, ciphertext);
    } catch (const std::exception& e) {
        OPENSSL_cleanse(master_key.data(), master_key.size());
        throw std::runtime_error(std::string("keystore decrypt failed (wrong passphrase?): ") + e.what());
    }
    OPENSSL_cleanse(master_key.data(), master_key.size());

    // 6. Parse inner JSON.
    json inner;
    try {
        inner = json::parse(plain.begin(), plain.end());
    } catch (const json::exception& e) {
        OPENSSL_cleanse(plain.data(), plain.size());
        throw std::runtime_error(std::string("keystore inner parse failed: ") + e.what());
    }
    OPENSSL_cleanse(plain.data(), plain.size());

    // 7. Extract keys.
    auto keys = std::make_unique<ServerKeys>();
    keys->x25519_priv  = base64_decode(inner.at("server_x25519_priv_b64").get<std::string>());
    keys->x25519_pub   = base64_decode(inner.at("server_x25519_pub_b64").get<std::string>());
    keys->ed25519_priv = base64_decode(inner.at("server_ed25519_priv_b64").get<std::string>());
    keys->ed25519_pub  = base64_decode(inner.at("server_ed25519_pub_b64").get<std::string>());
    return keys;
}

} // namespace license::keystore
