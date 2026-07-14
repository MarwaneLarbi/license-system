/**
 * test_crypto.cpp — Unit tests for crypto primitives.
 *
 * Covers:
 *  - base64 round-trip
 *  - sha256 known-answer
 *  - AES-256-GCM encrypt/decrypt round-trip and tamper detection
 *  - HKDF-SHA256 determinism
 *  - X25519 ECDH shared secret agreement
 *  - Ed25519 sign / verify
 *  - Hybrid encryption round-trip
 *  - Constant-time comparison
 */

#include <catch2/catch_test_macros.hpp>
#include "crypto.h"

#include <algorithm>
#include <string>
#include <vector>

using namespace license::crypto;

// ──────────────────────────────────────────────
// Base64
// ──────────────────────────────────────────────

TEST_CASE("base64 encode / decode round-trip", "[crypto][base64]") {
    SECTION("empty") {
        REQUIRE(base64_encode({}).empty());
        REQUIRE(base64_decode("").empty());
    }
    SECTION("single byte") {
        Bytes b{0x01};
        auto enc = base64_encode(b);
        REQUIRE(base64_decode(enc) == b);
    }
    SECTION("two bytes") {
        Bytes b{0xde, 0xad};
        auto enc = base64_encode(b);
        REQUIRE(base64_decode(enc) == b);
    }
    SECTION("three bytes (no padding)") {
        Bytes b{0x01, 0x02, 0x03};
        auto enc = base64_encode(b);
        REQUIRE(enc.size() == 4);
        REQUIRE(base64_decode(enc) == b);
    }
    SECTION("32 random bytes") {
        auto rnd = random_bytes(32);
        REQUIRE(base64_decode(base64_encode(rnd)) == rnd);
    }
    SECTION("1000 random bytes") {
        auto rnd = random_bytes(1000);
        REQUIRE(base64_decode(base64_encode(rnd)) == rnd);
    }
    SECTION("known value: Man") {
        Bytes b{'M', 'a', 'n'};
        REQUIRE(base64_encode(b) == "TWFu");
        REQUIRE(base64_decode("TWFu") == b);
    }
    SECTION("invalid base64 throws") {
        REQUIRE_THROWS(base64_decode("!!!!"));  // invalid chars
        REQUIRE_THROWS(base64_decode("ABC"));   // wrong length (not mod 4)
    }
}

// ──────────────────────────────────────────────
// SHA-256
// ──────────────────────────────────────────────

TEST_CASE("sha256 known-answer", "[crypto][sha256]") {
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    auto empty = sha256(std::string_view(""));
    REQUIRE(empty.size() == 32);
    REQUIRE(empty[0] == 0xe3);
    REQUIRE(empty[1] == 0xb0);
    REQUIRE(empty[31] == 0x55);

    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469348423f656c4efef0
    // (first byte ba, last byte f0 … just check length and byte 0)
    auto abc_hash = sha256(std::string_view("abc"));
    REQUIRE(abc_hash.size() == 32);
    REQUIRE(abc_hash[0] == 0xba);
}

TEST_CASE("sha256 span vs string_view produces same result", "[crypto][sha256]") {
    std::string data = "hello world";
    auto h1 = sha256(std::string_view(data));
    Bytes data_bytes(data.begin(), data.end());
    auto h2 = sha256(std::span<const uint8_t>(data_bytes));
    REQUIRE(h1 == h2);
}

// ──────────────────────────────────────────────
// Constant-time comparison
// ──────────────────────────────────────────────

TEST_CASE("ct_equal correctness", "[crypto][ct_equal]") {
    Bytes a{1, 2, 3};
    Bytes b{1, 2, 3};
    Bytes c{1, 2, 4};
    Bytes d{1, 2};
    REQUIRE(ct_equal(a, b) == true);
    REQUIRE(ct_equal(a, c) == false);
    REQUIRE(ct_equal(a, d) == false);  // different lengths → false
    REQUIRE(ct_equal(Bytes{}, Bytes{}) == true);
}

// ──────────────────────────────────────────────
// HKDF-SHA256
// ──────────────────────────────────────────────

TEST_CASE("HKDF-SHA256 deterministic output", "[crypto][hkdf]") {
    Bytes ikm(32, 0xaa);
    Bytes salt(16, 0xbb);
    Bytes info{'t', 'e', 's', 't'};

    auto k1 = hkdf_sha256(ikm, salt, info, 32);
    auto k2 = hkdf_sha256(ikm, salt, info, 32);
    REQUIRE(k1 == k2);
    REQUIRE(k1.size() == 32);
}

TEST_CASE("HKDF-SHA256 different info produces different key", "[crypto][hkdf]") {
    Bytes ikm(32, 0xaa);
    Bytes salt(16, 0xbb);
    Bytes info1{'a'};
    Bytes info2{'b'};
    REQUIRE(hkdf_sha256(ikm, salt, info1, 32) != hkdf_sha256(ikm, salt, info2, 32));
}

TEST_CASE("HKDF-SHA256 empty salt is accepted", "[crypto][hkdf]") {
    Bytes ikm(32, 0x11);
    Bytes info{'x'};
    auto k = hkdf_sha256(ikm, {}, info, 64);
    REQUIRE(k.size() == 64);
}

// ──────────────────────────────────────────────
// AES-256-GCM
// ──────────────────────────────────────────────

TEST_CASE("AES-256-GCM encrypt/decrypt round-trip", "[crypto][aes-gcm]") {
    auto key = random_bytes(32);
    Bytes aad{'a', 'a', 'd'};
    Bytes plain{'h', 'e', 'l', 'l', 'o'};

    auto ct = aes256gcm_encrypt(key, aad, plain);
    auto decr = aes256gcm_decrypt(key, aad, ct);
    REQUIRE(decr == plain);
}

TEST_CASE("AES-256-GCM empty plaintext", "[crypto][aes-gcm]") {
    auto key = random_bytes(32);
    auto ct = aes256gcm_encrypt(key, {}, {});
    REQUIRE(ct.size() == AeadParams::NONCE_LEN + AeadParams::TAG_LEN);
    auto decr = aes256gcm_decrypt(key, {}, ct);
    REQUIRE(decr.empty());
}

TEST_CASE("AES-256-GCM tampered ciphertext throws", "[crypto][aes-gcm]") {
    auto key = random_bytes(32);
    Bytes plain(100, 0x42);
    auto ct = aes256gcm_encrypt(key, {}, plain);
    ct[20] ^= 0x01;  // flip a bit in the ciphertext
    REQUIRE_THROWS(aes256gcm_decrypt(key, {}, ct));
}

TEST_CASE("AES-256-GCM tampered tag throws", "[crypto][aes-gcm]") {
    auto key = random_bytes(32);
    Bytes plain(50, 0x55);
    auto ct = aes256gcm_encrypt(key, {}, plain);
    ct.back() ^= 0xff;  // corrupt tag
    REQUIRE_THROWS(aes256gcm_decrypt(key, {}, ct));
}

TEST_CASE("AES-256-GCM wrong AAD throws", "[crypto][aes-gcm]") {
    auto key = random_bytes(32);
    Bytes plain(20, 0x01);
    Bytes aad{'a', 'a', 'd'};
    auto ct = aes256gcm_encrypt(key, aad, plain);
    Bytes wrong_aad{'w', 'r', 'o', 'n', 'g'};
    REQUIRE_THROWS(aes256gcm_decrypt(key, wrong_aad, ct));
}

TEST_CASE("AES-256-GCM nonce is unique per call", "[crypto][aes-gcm]") {
    auto key = random_bytes(32);
    Bytes plain(20, 0xaa);
    auto ct1 = aes256gcm_encrypt(key, {}, plain);
    auto ct2 = aes256gcm_encrypt(key, {}, plain);
    // Nonces (first 12 bytes) must differ (with overwhelming probability).
    bool nonce_same = std::equal(ct1.begin(), ct1.begin() + 12, ct2.begin(), ct2.begin() + 12);
    REQUIRE(!nonce_same);
}

TEST_CASE("AES-256-GCM wrong key length throws", "[crypto][aes-gcm]") {
    Bytes bad_key(16, 0x00);  // only 128 bits
    REQUIRE_THROWS(aes256gcm_encrypt(bad_key, {}, {0x01}));
    REQUIRE_THROWS(aes256gcm_decrypt(bad_key, {}, Bytes(28, 0x00)));
}

// ──────────────────────────────────────────────
// X25519
// ──────────────────────────────────────────────

TEST_CASE("X25519 ECDH: both parties derive same shared secret", "[crypto][x25519]") {
    auto alice = x25519_generate_keypair();
    auto bob = x25519_generate_keypair();

    auto ss_alice = x25519_exchange(alice.priv, bob.pub);
    auto ss_bob = x25519_exchange(bob.priv, alice.pub);

    REQUIRE(ss_alice.size() == 32);
    REQUIRE(ss_alice == ss_bob);
}

TEST_CASE("X25519 different key pairs produce different shared secrets", "[crypto][x25519]") {
    auto alice = x25519_generate_keypair();
    auto bob = x25519_generate_keypair();
    auto carol = x25519_generate_keypair();

    auto ss1 = x25519_exchange(alice.priv, bob.pub);
    auto ss2 = x25519_exchange(alice.priv, carol.pub);
    REQUIRE(ss1 != ss2);
}

// ──────────────────────────────────────────────
// Ed25519
// ──────────────────────────────────────────────

TEST_CASE("Ed25519 sign and verify", "[crypto][ed25519]") {
    auto kp = ed25519_generate_keypair();
    Bytes msg{'m', 'e', 's', 's', 'a', 'g', 'e'};
    auto sig = ed25519_sign(kp.priv, msg);
    REQUIRE(sig.size() == 64);
    REQUIRE(ed25519_verify(kp.pub, msg, sig) == true);
}

TEST_CASE("Ed25519 wrong public key fails verification", "[crypto][ed25519]") {
    auto kp1 = ed25519_generate_keypair();
    auto kp2 = ed25519_generate_keypair();
    Bytes msg{'t', 'e', 's', 't'};
    auto sig = ed25519_sign(kp1.priv, msg);
    REQUIRE(ed25519_verify(kp2.pub, msg, sig) == false);
}

TEST_CASE("Ed25519 tampered message fails verification", "[crypto][ed25519]") {
    auto kp = ed25519_generate_keypair();
    Bytes msg{0x01, 0x02, 0x03};
    auto sig = ed25519_sign(kp.priv, msg);
    msg[0] ^= 0x01;
    REQUIRE(ed25519_verify(kp.pub, msg, sig) == false);
}

TEST_CASE("Ed25519 tampered signature fails verification", "[crypto][ed25519]") {
    auto kp = ed25519_generate_keypair();
    Bytes msg{'a', 'b', 'c'};
    auto sig = ed25519_sign(kp.priv, msg);
    sig[0] ^= 0x01;
    REQUIRE(ed25519_verify(kp.pub, msg, sig) == false);
}

// ──────────────────────────────────────────────
// Hybrid encryption
// ──────────────────────────────────────────────

TEST_CASE("Hybrid encrypt/decrypt round-trip", "[crypto][hybrid]") {
    auto kp = x25519_generate_keypair();
    Bytes aad{'a', 'a', 'd'};
    Bytes plain(256, 0x42);

    auto ct = hybrid_encrypt(kp.pub, aad, plain);
    auto decr = hybrid_decrypt(kp.priv, aad, ct);
    REQUIRE(decr == plain);
}

TEST_CASE("Hybrid: wrong private key fails", "[crypto][hybrid]") {
    auto kp1 = x25519_generate_keypair();
    auto kp2 = x25519_generate_keypair();
    Bytes plain{'s', 'e', 'c', 'r', 'e', 't'};

    auto ct = hybrid_encrypt(kp1.pub, {}, plain);
    // Decrypt with wrong key → AES-GCM auth will fail.
    REQUIRE_THROWS(hybrid_decrypt(kp2.priv, {}, ct));
}

TEST_CASE("Hybrid: wrong AAD fails", "[crypto][hybrid]") {
    auto kp = x25519_generate_keypair();
    Bytes aad{'a', 'a', 'd'};
    Bytes plain{'d', 'a', 't', 'a'};

    auto ct = hybrid_encrypt(kp.pub, aad, plain);
    Bytes bad_aad{'x', 'y', 'z'};
    REQUIRE_THROWS(hybrid_decrypt(kp.priv, bad_aad, ct));
}

TEST_CASE("Hybrid: tampered ciphertext fails", "[crypto][hybrid]") {
    auto kp = x25519_generate_keypair();
    Bytes plain(100, 0x55);
    auto ct = hybrid_encrypt(kp.pub, {}, plain);
    ct[40] ^= 0x01;  // corrupt payload
    REQUIRE_THROWS(hybrid_decrypt(kp.priv, {}, ct));
}
