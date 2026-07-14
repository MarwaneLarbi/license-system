/**
 * test_license.cpp — Unit tests for license record serialisation,
 *                    token signing/verification, and anti-replay helpers.
 */

#include <catch2/catch_test_macros.hpp>
#include "license.h"
#include "crypto.h"
#include "keystore.h"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;
using namespace license;

// ──────────────────────────────────────────────
// LicenseRequest serialisation
// ──────────────────────────────────────────────

TEST_CASE("LicenseRequest serialise / deserialise round-trip", "[license][request]") {
    LicenseRequest req;
    req.product_id = "myapp-pro";
    req.customer_hint = "alice@example.com";
    req.fingerprint_hash = std::string(64, 'a');
    req.fingerprint_assurance = "hardware";
    req.device_pubkey_b64 = "dGVzdA==";
    req.timestamp = 1700000000;
    req.nonce = "bm9uY2U=";

    auto json = to_json(req);
    auto parsed = request_from_json(json);

    REQUIRE(parsed.product_id == req.product_id);
    REQUIRE(parsed.customer_hint == req.customer_hint);
    REQUIRE(parsed.fingerprint_hash == req.fingerprint_hash);
    REQUIRE(parsed.fingerprint_assurance == req.fingerprint_assurance);
    REQUIRE(parsed.device_pubkey_b64 == req.device_pubkey_b64);
    REQUIRE(parsed.timestamp == req.timestamp);
    REQUIRE(parsed.nonce == req.nonce);
}

TEST_CASE("request_from_json throws on missing required field", "[license][request]") {
    REQUIRE_THROWS(request_from_json("{}"));
    REQUIRE_THROWS(request_from_json("{\"product_id\":\"x\"}"));
    REQUIRE_THROWS(request_from_json("not json"));
}

// ──────────────────────────────────────────────
// LicenseRecord serialisation
// ──────────────────────────────────────────────

TEST_CASE("LicenseRecord serialise / deserialise round-trip", "[license][record]") {
    LicenseRecord rec;
    rec.license_id = "abc-123";
    rec.product_id = "myapp-pro";
    rec.fingerprint_hash = std::string(64, 'f');
    rec.fingerprint_assurance = "software";
    rec.features = {"feature-a", "feature-b"};
    rec.issued_at = 1700000000;
    rec.expires_at = 1700000000 + 86400 * 365;
    rec.max_activations = 3;

    auto json = to_json(rec);
    auto parsed = record_from_json(json);

    REQUIRE(parsed.license_id == rec.license_id);
    REQUIRE(parsed.product_id == rec.product_id);
    REQUIRE(parsed.fingerprint_hash == rec.fingerprint_hash);
    REQUIRE(parsed.fingerprint_assurance == rec.fingerprint_assurance);
    REQUIRE(parsed.features == rec.features);
    REQUIRE(parsed.issued_at == rec.issued_at);
    REQUIRE(parsed.expires_at == rec.expires_at);
    REQUIRE(parsed.max_activations == rec.max_activations);
}

// ──────────────────────────────────────────────
// Token: sign and verify
// ──────────────────────────────────────────────

static LicenseRecord make_test_record(int64_t expires_at = 0) {
    LicenseRecord rec;
    rec.license_id = generate_uuid();
    rec.product_id = "test-product";
    rec.fingerprint_hash = std::string(64, '0');
    rec.fingerprint_assurance = "software";
    rec.features = {"basic", "advanced"};
    rec.issued_at = 1700000000;
    rec.expires_at = expires_at;
    rec.max_activations = 1;
    return rec;
}

TEST_CASE("sign_license / verify_license round-trip", "[license][token]") {
    auto kp = crypto::ed25519_generate_keypair();
    auto rec = make_test_record(0);  // no expiry

    auto token = sign_license(rec, kp.priv);
    REQUIRE(!token.empty());

    // Token format: <base64>.<base64>
    auto dot = token.find('.');
    REQUIRE(dot != std::string::npos);
    REQUIRE(dot > 0);
    REQUIRE(token.size() > dot + 1);

    auto vr = verify_license(token, kp.pub);
    REQUIRE(vr.valid == true);
    REQUIRE(vr.record.license_id == rec.license_id);
    REQUIRE(vr.record.product_id == rec.product_id);
    REQUIRE(vr.record.features == rec.features);
    REQUIRE(vr.record.expires_at == rec.expires_at);
}

TEST_CASE("verify_license: wrong public key fails", "[license][token]") {
    auto kp1 = crypto::ed25519_generate_keypair();
    auto kp2 = crypto::ed25519_generate_keypair();
    auto rec = make_test_record(0);

    auto token = sign_license(rec, kp1.priv);
    auto vr = verify_license(token, kp2.pub);
    REQUIRE(vr.valid == false);
    REQUIRE(!vr.error.empty());
}

TEST_CASE("verify_license: tampered payload fails", "[license][token]") {
    auto kp = crypto::ed25519_generate_keypair();
    auto rec = make_test_record(0);
    auto token = sign_license(rec, kp.priv);

    // Corrupt a character in the payload portion.
    auto dot = token.find('.');
    token[dot / 2] ^= 0x01;

    auto vr = verify_license(token, kp.pub);
    REQUIRE(vr.valid == false);
}

TEST_CASE("verify_license: tampered signature fails", "[license][token]") {
    auto kp = crypto::ed25519_generate_keypair();
    auto rec = make_test_record(0);
    auto token = sign_license(rec, kp.priv);

    // Corrupt a character in the signature portion.
    auto dot = token.rfind('.');
    if (dot + 4 < token.size())
        token[dot + 2] ^= 0x01;
    else
        token.back() ^= 0x01;

    auto vr = verify_license(token, kp.pub);
    REQUIRE(vr.valid == false);
}

TEST_CASE("verify_license: expired license fails", "[license][token]") {
    auto kp = crypto::ed25519_generate_keypair();
    auto rec = make_test_record(/*expires_at=*/1);  // expired in 1970
    auto token = sign_license(rec, kp.priv);
    auto vr = verify_license(token, kp.pub);
    REQUIRE(vr.valid == false);
    REQUIRE(vr.error.find("expired") != std::string::npos);
}

TEST_CASE("verify_license: non-expired license passes", "[license][token]") {
    auto kp = crypto::ed25519_generate_keypair();
    int64_t far_future = 9999999999LL;  // year 2286
    auto rec = make_test_record(far_future);
    auto token = sign_license(rec, kp.priv);
    auto vr = verify_license(token, kp.pub);
    REQUIRE(vr.valid == true);
}

TEST_CASE("verify_license: no-expiry license (expires_at=0) passes", "[license][token]") {
    auto kp = crypto::ed25519_generate_keypair();
    auto rec = make_test_record(0);
    auto vr = verify_license(sign_license(rec, kp.priv), kp.pub);
    REQUIRE(vr.valid == true);
}

TEST_CASE("verify_license: malformed token fails gracefully", "[license][token]") {
    auto kp = crypto::ed25519_generate_keypair();
    REQUIRE(verify_license("", kp.pub).valid == false);
    REQUIRE(verify_license("nodot", kp.pub).valid == false);
    REQUIRE(verify_license("!!!.!!!", kp.pub).valid == false);
}

// ──────────────────────────────────────────────
// generate_uuid
// ──────────────────────────────────────────────

TEST_CASE("generate_uuid produces unique values", "[license][uuid]") {
    auto u1 = generate_uuid();
    auto u2 = generate_uuid();
    REQUIRE(u1.size() == 36);  // "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    REQUIRE(u1 != u2);
    // Check version nibble = '4'.
    REQUIRE(u1[14] == '4');
    // Check variant nibble = '8', '9', 'a', or 'b'.
    char var = u1[19];
    REQUIRE((var == '8' || var == '9' || var == 'a' || var == 'b'));
}

// ──────────────────────────────────────────────
// Anti-replay: timestamp_is_fresh
// ──────────────────────────────────────────────

TEST_CASE("timestamp_is_fresh: current time is fresh", "[license][replay]") {
    auto now = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count());
    REQUIRE(timestamp_is_fresh(now) == true);
}

TEST_CASE("timestamp_is_fresh: 5 minutes ago is fresh", "[license][replay]") {
    auto now = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count());
    REQUIRE(timestamp_is_fresh(now - 300) == true);
}

TEST_CASE("timestamp_is_fresh: 25 hours ago is stale", "[license][replay]") {
    auto now = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count());
    REQUIRE(timestamp_is_fresh(now - 90000) == false);
}

TEST_CASE("timestamp_is_fresh: future timestamp is stale", "[license][replay]") {
    auto now = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count());
    REQUIRE(timestamp_is_fresh(now + 100) == false);
}

// ──────────────────────────────────────────────
// Keystore: generate and load round-trip
// ──────────────────────────────────────────────

TEST_CASE("keystore generate and load round-trip", "[keystore]") {
    auto tmp_path = fs::temp_directory_path() / "test_keystore.json";
    auto path_str = tmp_path.string();

    const std::string passphrase = "test-passphrase-do-not-use-in-production";

    // Use very low Argon2 cost for test speed.
    keystore::Argon2Params fast{.t_cost = 1, .m_cost = 8192, .parallelism = 1};

    keystore::PublicKeys pub;
    REQUIRE_NOTHROW(pub = keystore::generate_keystore(path_str, passphrase, fast, nullptr));
    REQUIRE(!pub.x25519_pub_b64.empty());
    REQUIRE(!pub.ed25519_pub_b64.empty());

    std::unique_ptr<keystore::ServerKeys> keys;
    REQUIRE_NOTHROW(keys = keystore::load_keystore(path_str, passphrase, nullptr));
    REQUIRE(keys->x25519_pub.size() == 32);
    REQUIRE(keys->x25519_priv.size() == 32);
    REQUIRE(keys->ed25519_pub.size() == 32);

    // Verify the public key in the keystore matches what generate_keystore returned.
    auto loaded_pub_b64 = crypto::base64_encode(keys->ed25519_pub);
    REQUIRE(loaded_pub_b64 == pub.ed25519_pub_b64);

    // Clean up.
    fs::remove(tmp_path);
}

TEST_CASE("keystore: wrong passphrase throws", "[keystore]") {
    auto tmp_path = fs::temp_directory_path() / "test_keystore_bad.json";
    keystore::Argon2Params fast{.t_cost = 1, .m_cost = 8192, .parallelism = 1};
    (void)keystore::generate_keystore(tmp_path.string(), "correct", fast, nullptr);
    REQUIRE_THROWS(keystore::load_keystore(tmp_path.string(), "wrong", nullptr));
    fs::remove(tmp_path);
}

TEST_CASE("keystore: generated keys can sign and verify a license", "[keystore]") {
    auto tmp_path = fs::temp_directory_path() / "test_keystore_sign.json";
    keystore::Argon2Params fast{.t_cost = 1, .m_cost = 8192, .parallelism = 1};
    (void)keystore::generate_keystore(tmp_path.string(), "passphrase", fast, nullptr);
    auto keys = keystore::load_keystore(tmp_path.string(), "passphrase", nullptr);

    auto rec = make_test_record(0);
    auto token = sign_license(rec, keys->ed25519_priv);
    auto vr = verify_license(token, keys->ed25519_pub);
    REQUIRE(vr.valid == true);

    fs::remove(tmp_path);
}
