/**
 * crypto.cpp — OpenSSL 3.x EVP-based cryptographic primitives.
 *
 * Rules:
 *  - EVP API only; no deprecated low-level calls (no RSA_*, no EC_KEY_*, etc.)
 *  - No key material is ever written to a stream or logged.
 *  - Random bytes come exclusively from OpenSSL (RAND_bytes).
 */

#include "crypto.h"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <array>
#include <cassert>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string_view>

namespace license::crypto {

// ──────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────

namespace {

// RAII wrappers for OpenSSL objects.
struct EvpPkeyDeleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct EvpPkeyCtxDeleter { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
struct EvpCipherCtxDeleter { void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); } };
struct EvpKdfDeleter { void operator()(EVP_KDF* p) const { EVP_KDF_free(p); } };
struct EvpKdfCtxDeleter { void operator()(EVP_KDF_CTX* p) const { EVP_KDF_CTX_free(p); } };
struct EvpMdCtxDeleter { void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); } };

using UniqueEvpPkey    = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using UniqueEvpPkeyCtx = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using UniqueCipherCtx  = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;
using UniqueEvpKdf     = std::unique_ptr<EVP_KDF, EvpKdfDeleter>;
using UniqueEvpKdfCtx  = std::unique_ptr<EVP_KDF_CTX, EvpKdfCtxDeleter>;
using UniqueEvpMdCtx   = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

/// Collect and throw the OpenSSL error queue.
[[noreturn]] void throw_openssl(std::string_view context) {
    char buf[256]{};
    ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
    throw std::runtime_error(std::string(context) + ": " + buf);
}

/// Load a raw private key for an EVP algorithm.
UniqueEvpPkey evp_pkey_from_raw_priv(int nid,
                                      const uint8_t* raw,
                                      std::size_t    len)
{
    UniqueEvpPkey key{ EVP_PKEY_new_raw_private_key(nid, nullptr, raw, len) };
    if (!key) throw_openssl("EVP_PKEY_new_raw_private_key");
    return key;
}

/// Load a raw public key for an EVP algorithm.
UniqueEvpPkey evp_pkey_from_raw_pub(int nid,
                                     const uint8_t* raw,
                                     std::size_t    len)
{
    UniqueEvpPkey key{ EVP_PKEY_new_raw_public_key(nid, nullptr, raw, len) };
    if (!key) throw_openssl("EVP_PKEY_new_raw_public_key");
    return key;
}

// Base64 alphabet (standard, with padding).
constexpr std::string_view B64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

} // anonymous namespace

// ──────────────────────────────────────────────
// Base64
// ──────────────────────────────────────────────

std::string base64_encode(std::span<const uint8_t> data) {
    if (data.empty()) return {};
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    auto* p = data.data();
    std::size_t rem = data.size();
    while (rem >= 3) {
        uint32_t v = (static_cast<uint32_t>(p[0]) << 16)
                   | (static_cast<uint32_t>(p[1]) <<  8)
                   |  static_cast<uint32_t>(p[2]);
        out += B64_CHARS[(v >> 18) & 0x3f];
        out += B64_CHARS[(v >> 12) & 0x3f];
        out += B64_CHARS[(v >>  6) & 0x3f];
        out += B64_CHARS[(v      ) & 0x3f];
        p   += 3;
        rem -= 3;
    }
    if (rem == 1) {
        uint32_t v = static_cast<uint32_t>(p[0]) << 16;
        out += B64_CHARS[(v >> 18) & 0x3f];
        out += B64_CHARS[(v >> 12) & 0x3f];
        out += '='; out += '=';
    } else if (rem == 2) {
        uint32_t v = (static_cast<uint32_t>(p[0]) << 16)
                   | (static_cast<uint32_t>(p[1]) <<  8);
        out += B64_CHARS[(v >> 18) & 0x3f];
        out += B64_CHARS[(v >> 12) & 0x3f];
        out += B64_CHARS[(v >>  6) & 0x3f];
        out += '=';
    }
    return out;
}

Bytes base64_decode(std::string_view b64) {
    if (b64.empty()) return {};
    // Build decode table.
    static const auto DEC = []() {
        std::array<int8_t, 256> t{};
        t.fill(-1);
        for (int i = 0; i < 64; ++i) t[static_cast<uint8_t>(B64_CHARS[i])] = static_cast<int8_t>(i);
        t['='] = 0;
        return t;
    }();

    // Strip whitespace and validate padding.
    std::string stripped;
    stripped.reserve(b64.size());
    for (char c : b64) {
        if (c != '\n' && c != '\r' && c != ' ') stripped += c;
    }
    if (stripped.size() % 4 != 0)
        throw std::runtime_error("base64_decode: invalid length");

    Bytes out;
    out.reserve(stripped.size() / 4 * 3);
    for (std::size_t i = 0; i < stripped.size(); i += 4) {
        int8_t a = DEC[static_cast<uint8_t>(stripped[i])];
        int8_t b = DEC[static_cast<uint8_t>(stripped[i+1])];
        int8_t c = DEC[static_cast<uint8_t>(stripped[i+2])];
        int8_t d = DEC[static_cast<uint8_t>(stripped[i+3])];
        if (a < 0 || b < 0 || c < 0 || d < 0)
            throw std::runtime_error("base64_decode: invalid character");
        uint32_t v = (static_cast<uint32_t>(a) << 18)
                   | (static_cast<uint32_t>(b) << 12)
                   | (static_cast<uint32_t>(c) <<  6)
                   |  static_cast<uint32_t>(d);
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
        if (stripped[i+2] != '=') out.push_back(static_cast<uint8_t>((v >>  8) & 0xff));
        if (stripped[i+3] != '=') out.push_back(static_cast<uint8_t>( v        & 0xff));
    }
    return out;
}

// ──────────────────────────────────────────────
// Random bytes
// ──────────────────────────────────────────────

void random_bytes(uint8_t* out, std::size_t n) {
    if (RAND_bytes(out, static_cast<int>(n)) != 1)
        throw_openssl("RAND_bytes");
}

Bytes random_bytes(std::size_t n) {
    Bytes out(n);
    random_bytes(out.data(), n);
    return out;
}

// ──────────────────────────────────────────────
// Constant-time comparison
// ──────────────────────────────────────────────

bool ct_equal(std::span<const uint8_t> a, std::span<const uint8_t> b) {
    if (a.size() != b.size()) return false;
    // CRYPTO_memcmp is constant-time in OpenSSL.
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

// ──────────────────────────────────────────────
// SHA-256
// ──────────────────────────────────────────────

Bytes sha256(std::span<const uint8_t> data) {
    Bytes digest(EVP_MAX_MD_SIZE);
    unsigned len = 0;
    UniqueEvpMdCtx ctx{ EVP_MD_CTX_new() };
    if (!ctx ||
        EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx.get(), digest.data(), &len) != 1)
    {
        throw_openssl("sha256");
    }
    digest.resize(len);
    return digest;
}

Bytes sha256(std::string_view data) {
    return sha256(std::span<const uint8_t>{
        reinterpret_cast<const uint8_t*>(data.data()), data.size()});
}

// ──────────────────────────────────────────────
// HKDF-SHA256
// ──────────────────────────────────────────────

Bytes hkdf_sha256(std::span<const uint8_t> ikm,
                  std::span<const uint8_t> salt,
                  std::span<const uint8_t> info,
                  std::size_t              len)
{
    UniqueEvpKdf kdf{ EVP_KDF_fetch(nullptr, "HKDF", nullptr) };
    if (!kdf) throw_openssl("EVP_KDF_fetch HKDF");
    UniqueEvpKdfCtx ctx{ EVP_KDF_CTX_new(kdf.get()) };
    if (!ctx) throw_openssl("EVP_KDF_CTX_new");

    std::array<OSSL_PARAM, 5> params{};
    std::size_t pi = 0;
    const char* digest_name = "SHA256";
    params[pi++] = OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST,
        const_cast<char*>(digest_name), 0);
    params[pi++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY,
        const_cast<uint8_t*>(ikm.data()), ikm.size());
    if (!salt.empty())
        params[pi++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT,
            const_cast<uint8_t*>(salt.data()), salt.size());
    if (!info.empty())
        params[pi++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO,
            const_cast<uint8_t*>(info.data()), info.size());
    params[pi] = OSSL_PARAM_END;

    Bytes out(len);
    if (EVP_KDF_derive(ctx.get(), out.data(), len, params.data()) != 1)
        throw_openssl("EVP_KDF_derive HKDF");
    return out;
}

// ──────────────────────────────────────────────
// AES-256-GCM
// ──────────────────────────────────────────────

Bytes aes256gcm_encrypt(std::span<const uint8_t> key,
                        std::span<const uint8_t> aad,
                        std::span<const uint8_t> plain)
{
    if (key.size() != AeadParams::KEY_LEN)
        throw std::invalid_argument("aes256gcm_encrypt: key must be 32 bytes");

    // Generate unique nonce.
    auto nonce = random_bytes(AeadParams::NONCE_LEN);

    UniqueCipherCtx ctx{ EVP_CIPHER_CTX_new() };
    if (!ctx) throw_openssl("EVP_CIPHER_CTX_new");

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw_openssl("EVP_EncryptInit_ex");
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                             static_cast<int>(AeadParams::NONCE_LEN), nullptr) != 1)
        throw_openssl("EVP_CTRL_GCM_SET_IVLEN");
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw_openssl("EVP_EncryptInit_ex (key/nonce)");

    // AAD.
    if (!aad.empty()) {
        int outlen = 0;
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &outlen,
                               aad.data(), static_cast<int>(aad.size())) != 1)
            throw_openssl("EVP_EncryptUpdate AAD");
    }

    // Encrypt.
    Bytes ct(plain.size() + EVP_MAX_BLOCK_LENGTH);
    int len1 = 0, len2 = 0;
    if (plain.empty()) {
        // EVP_EncryptUpdate with null input is fine; just skip.
        len1 = 0;
    } else {
        if (EVP_EncryptUpdate(ctx.get(), ct.data(), &len1,
                               plain.data(), static_cast<int>(plain.size())) != 1)
            throw_openssl("EVP_EncryptUpdate");
    }
    if (EVP_EncryptFinal_ex(ctx.get(), ct.data() + len1, &len2) != 1)
        throw_openssl("EVP_EncryptFinal_ex");
    ct.resize(static_cast<std::size_t>(len1 + len2));

    // Tag.
    Bytes tag(AeadParams::TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                              static_cast<int>(AeadParams::TAG_LEN), tag.data()) != 1)
        throw_openssl("EVP_CTRL_GCM_GET_TAG");

    // Output: nonce || ct || tag.
    Bytes out;
    out.reserve(nonce.size() + ct.size() + tag.size());
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), ct.begin(),   ct.end());
    out.insert(out.end(), tag.begin(),  tag.end());
    return out;
}

Bytes aes256gcm_decrypt(std::span<const uint8_t> key,
                        std::span<const uint8_t> aad,
                        std::span<const uint8_t> ciphertext)
{
    if (key.size() != AeadParams::KEY_LEN)
        throw std::invalid_argument("aes256gcm_decrypt: key must be 32 bytes");
    constexpr std::size_t OVERHEAD = AeadParams::NONCE_LEN + AeadParams::TAG_LEN;
    if (ciphertext.size() < OVERHEAD)
        throw std::runtime_error("aes256gcm_decrypt: ciphertext too short");

    auto nonce  = ciphertext.subspan(0, AeadParams::NONCE_LEN);
    auto ct     = ciphertext.subspan(AeadParams::NONCE_LEN,
                                     ciphertext.size() - OVERHEAD);
    // Tag is at the end (mutable copy for OpenSSL).
    Bytes tag(ciphertext.end() - AeadParams::TAG_LEN, ciphertext.end());

    UniqueCipherCtx ctx{ EVP_CIPHER_CTX_new() };
    if (!ctx) throw_openssl("EVP_CIPHER_CTX_new (dec)");

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw_openssl("EVP_DecryptInit_ex");
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                             static_cast<int>(AeadParams::NONCE_LEN), nullptr) != 1)
        throw_openssl("EVP_CTRL_GCM_SET_IVLEN (dec)");
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw_openssl("EVP_DecryptInit_ex (key/nonce)");

    if (!aad.empty()) {
        int outlen = 0;
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &outlen,
                               aad.data(), static_cast<int>(aad.size())) != 1)
            throw_openssl("EVP_DecryptUpdate AAD (dec)");
    }

    Bytes plain(ct.size() + EVP_MAX_BLOCK_LENGTH);
    int len1 = 0;
    if (!ct.empty()) {
        if (EVP_DecryptUpdate(ctx.get(), plain.data(), &len1,
                               ct.data(), static_cast<int>(ct.size())) != 1)
            throw_openssl("EVP_DecryptUpdate (dec)");
    }

    // Set expected tag.
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                              static_cast<int>(AeadParams::TAG_LEN), tag.data()) != 1)
        throw_openssl("EVP_CTRL_GCM_SET_TAG");

    int len2 = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plain.data() + len1, &len2) != 1)
        throw std::runtime_error("aes256gcm_decrypt: authentication failed (tag mismatch)");

    plain.resize(static_cast<std::size_t>(len1 + len2));
    return plain;
}

// ──────────────────────────────────────────────
// X25519
// ──────────────────────────────────────────────

X25519KeyPair x25519_generate_keypair() {
    UniqueEvpPkeyCtx ctx{ EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr) };
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1)
        throw_openssl("EVP_PKEY_keygen_init X25519");

    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) != 1)
        throw_openssl("EVP_PKEY_keygen X25519");
    UniqueEvpPkey key{ raw };

    X25519KeyPair kp;
    std::size_t pub_len = 32, priv_len = 32;
    kp.pub.resize(pub_len);
    kp.priv.resize(priv_len);
    if (EVP_PKEY_get_raw_public_key(key.get(), kp.pub.data(), &pub_len) != 1 ||
        EVP_PKEY_get_raw_private_key(key.get(), kp.priv.data(), &priv_len) != 1)
    {
        throw_openssl("EVP_PKEY_get_raw_key X25519");
    }
    return kp;
}

Bytes x25519_exchange(std::span<const uint8_t> our_priv,
                      std::span<const uint8_t> peer_pub)
{
    auto our  = evp_pkey_from_raw_priv(EVP_PKEY_X25519, our_priv.data(), our_priv.size());
    auto peer = evp_pkey_from_raw_pub (EVP_PKEY_X25519, peer_pub.data(), peer_pub.size());

    UniqueEvpPkeyCtx ctx{ EVP_PKEY_CTX_new(our.get(), nullptr) };
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1)
        throw_openssl("EVP_PKEY_derive_init X25519");
    if (EVP_PKEY_derive_set_peer(ctx.get(), peer.get()) != 1)
        throw_openssl("EVP_PKEY_derive_set_peer");

    std::size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &secret_len) != 1)
        throw_openssl("EVP_PKEY_derive (size)");

    Bytes secret(secret_len);
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &secret_len) != 1)
        throw_openssl("EVP_PKEY_derive");
    secret.resize(secret_len);
    return secret;
}

// ──────────────────────────────────────────────
// Ed25519
// ──────────────────────────────────────────────

Ed25519KeyPair ed25519_generate_keypair() {
    UniqueEvpPkeyCtx ctx{ EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr) };
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1)
        throw_openssl("EVP_PKEY_keygen_init Ed25519");

    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) != 1)
        throw_openssl("EVP_PKEY_keygen Ed25519");
    UniqueEvpPkey key{ raw };

    Ed25519KeyPair kp;
    std::size_t pub_len = 32, priv_len = 32;
    kp.pub.resize(pub_len);
    kp.priv.resize(priv_len);
    if (EVP_PKEY_get_raw_public_key(key.get(), kp.pub.data(), &pub_len) != 1 ||
        EVP_PKEY_get_raw_private_key(key.get(), kp.priv.data(), &priv_len) != 1)
    {
        throw_openssl("EVP_PKEY_get_raw_key Ed25519");
    }
    // Extend priv to 64-byte seed||pub form for convenience.
    kp.priv.insert(kp.priv.end(), kp.pub.begin(), kp.pub.end());
    return kp;
}

Bytes ed25519_sign(std::span<const uint8_t> priv_key,
                   std::span<const uint8_t> message)
{
    // Accept either 32-byte seed or 64-byte seed||pub.
    auto key = evp_pkey_from_raw_priv(EVP_PKEY_ED25519, priv_key.data(), 32);

    UniqueEvpMdCtx ctx{ EVP_MD_CTX_new() };
    if (!ctx) throw_openssl("EVP_MD_CTX_new Ed25519 sign");
    if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1)
        throw_openssl("EVP_DigestSignInit");

    std::size_t sig_len = 64;
    Bytes sig(sig_len);
    if (EVP_DigestSign(ctx.get(), sig.data(), &sig_len,
                        message.data(), message.size()) != 1)
        throw_openssl("EVP_DigestSign");
    sig.resize(sig_len);
    return sig;
}

bool ed25519_verify(std::span<const uint8_t> pub_key,
                    std::span<const uint8_t> message,
                    std::span<const uint8_t> signature)
{
    auto key = evp_pkey_from_raw_pub(EVP_PKEY_ED25519, pub_key.data(), pub_key.size());

    UniqueEvpMdCtx ctx{ EVP_MD_CTX_new() };
    if (!ctx) throw_openssl("EVP_MD_CTX_new Ed25519 verify");
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1)
        throw_openssl("EVP_DigestVerifyInit");

    // EVP_DigestVerify returns 1 on success, 0 on failure, -1 on error.
    int rc = EVP_DigestVerify(ctx.get(), signature.data(), signature.size(),
                               message.data(), message.size());
    if (rc < 0) throw_openssl("EVP_DigestVerify error");
    return rc == 1; // constant-time internally in OpenSSL
}

// ──────────────────────────────────────────────
// Hybrid encryption
// ──────────────────────────────────────────────

// HKDF info labels — must match on both sides.
static constexpr std::string_view HYBRID_HKDF_INFO = "license-hybrid-v1";

Bytes hybrid_encrypt(std::span<const uint8_t> recipient_pub,
                     std::span<const uint8_t> aad,
                     std::span<const uint8_t> plaintext)
{
    // 1. Generate ephemeral X25519 keypair.
    auto ephemeral = x25519_generate_keypair();

    // 2. ECDH: shared secret.
    auto dh_secret = x25519_exchange(ephemeral.priv, recipient_pub);

    // 3. HKDF-SHA256: derive 32-byte AES key.
    //    salt = ephemeral pub, info = "license-hybrid-v1"
    auto aes_key = hkdf_sha256(
        dh_secret,
        ephemeral.pub,
        std::span<const uint8_t>{
            reinterpret_cast<const uint8_t*>(HYBRID_HKDF_INFO.data()),
            HYBRID_HKDF_INFO.size()},
        32);

    // 4. AES-256-GCM encrypt.
    auto ct = aes256gcm_encrypt(aes_key, aad, plaintext);

    // 5. Output: ephemeral_pub (32 B) || nonce (12 B) || ciphertext || tag (16 B).
    Bytes out;
    out.reserve(32 + ct.size());
    out.insert(out.end(), ephemeral.pub.begin(), ephemeral.pub.end());
    out.insert(out.end(), ct.begin(), ct.end());

    // Wipe sensitive material.
    OPENSSL_cleanse(dh_secret.data(), dh_secret.size());
    OPENSSL_cleanse(aes_key.data(), aes_key.size());
    return out;
}

Bytes hybrid_decrypt(std::span<const uint8_t> recipient_priv,
                     std::span<const uint8_t> aad,
                     std::span<const uint8_t> ciphertext)
{
    constexpr std::size_t EPH_PUB_LEN = 32;
    constexpr std::size_t MIN_LEN =
        EPH_PUB_LEN + AeadParams::NONCE_LEN + AeadParams::TAG_LEN;

    if (ciphertext.size() < MIN_LEN)
        throw std::runtime_error("hybrid_decrypt: ciphertext too short");

    auto eph_pub = ciphertext.subspan(0, EPH_PUB_LEN);
    auto ct_blob = ciphertext.subspan(EPH_PUB_LEN);

    // 1. ECDH.
    auto dh_secret = x25519_exchange(recipient_priv, eph_pub);

    // 2. HKDF.
    auto aes_key = hkdf_sha256(
        dh_secret,
        eph_pub,
        std::span<const uint8_t>{
            reinterpret_cast<const uint8_t*>(HYBRID_HKDF_INFO.data()),
            HYBRID_HKDF_INFO.size()},
        32);

    // 3. AES-256-GCM decrypt.
    auto plain = aes256gcm_decrypt(aes_key, aad, ct_blob);

    OPENSSL_cleanse(dh_secret.data(), dh_secret.size());
    OPENSSL_cleanse(aes_key.data(), aes_key.size());
    return plain;
}

} // namespace license::crypto
