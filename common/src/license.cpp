/**
 * license.cpp — License record serialisation, token format, and verification.
 */

#include "license.h"
#include "crypto.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace license {

using json = nlohmann::json;

// ──────────────────────────────────────────────
// UUID generator (RFC-4122 v4)
// ──────────────────────────────────────────────

std::string generate_uuid() {
    auto rnd = crypto::random_bytes(16);
    // Set version = 4.
    rnd[6] = static_cast<uint8_t>((rnd[6] & 0x0f) | 0x40);
    // Set variant = 10xxxxxx.
    rnd[8] = static_cast<uint8_t>((rnd[8] & 0x3f) | 0x80);

    char buf[37];
    snprintf(buf, sizeof(buf),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
             "%02x%02x%02x%02x%02x%02x",
             rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5], rnd[6], rnd[7], rnd[8], rnd[9],
             rnd[10], rnd[11], rnd[12], rnd[13], rnd[14], rnd[15]);
    return buf;
}

// ──────────────────────────────────────────────
// LicenseRequest serialisation
// ──────────────────────────────────────────────

std::string to_json(const LicenseRequest& req) {
    // Sorted keys for deterministic output.
    json j;
    j["customer_hint"] = req.customer_hint;
    j["device_pubkey_b64"] = req.device_pubkey_b64;
    j["fingerprint_assurance"] = req.fingerprint_assurance;
    j["fingerprint_hash"] = req.fingerprint_hash;
    j["nonce"] = req.nonce;
    j["product_id"] = req.product_id;
    j["timestamp"] = req.timestamp;
    return j.dump();  // no extra whitespace
}

LicenseRequest request_from_json(const std::string& js) {
    try {
        auto j = json::parse(js);
        LicenseRequest req;
        req.product_id = j.at("product_id").get<std::string>();
        req.customer_hint = j.at("customer_hint").get<std::string>();
        req.fingerprint_hash = j.at("fingerprint_hash").get<std::string>();
        req.fingerprint_assurance = j.value("fingerprint_assurance", "software");
        req.device_pubkey_b64 = j.at("device_pubkey_b64").get<std::string>();
        req.timestamp = j.at("timestamp").get<int64_t>();
        req.nonce = j.at("nonce").get<std::string>();
        return req;
    } catch (const json::exception& e) {
        throw std::runtime_error(std::string("request_from_json: ") + e.what());
    }
}

// ──────────────────────────────────────────────
// LicenseRecord serialisation
// ──────────────────────────────────────────────

std::string to_json(const LicenseRecord& rec) {
    json j;
    j["expires_at"] = rec.expires_at;
    j["features"] = rec.features;
    j["fingerprint_assurance"] = rec.fingerprint_assurance;
    j["fingerprint_hash"] = rec.fingerprint_hash;
    j["issued_at"] = rec.issued_at;
    j["license_id"] = rec.license_id;
    j["max_activations"] = rec.max_activations;
    j["product_id"] = rec.product_id;
    return j.dump();
}

LicenseRecord record_from_json(const std::string& js) {
    try {
        auto j = json::parse(js);
        LicenseRecord rec;
        rec.license_id = j.at("license_id").get<std::string>();
        rec.product_id = j.at("product_id").get<std::string>();
        rec.fingerprint_hash = j.at("fingerprint_hash").get<std::string>();
        rec.fingerprint_assurance = j.value("fingerprint_assurance", "software");
        rec.features = j.at("features").get<FeatureList>();
        rec.issued_at = j.at("issued_at").get<int64_t>();
        rec.expires_at = j.at("expires_at").get<int64_t>();
        rec.max_activations = j.at("max_activations").get<uint32_t>();
        return rec;
    } catch (const json::exception& e) {
        throw std::runtime_error(std::string("record_from_json: ") + e.what());
    }
}

// ──────────────────────────────────────────────
// Token: sign_license
// ──────────────────────────────────────────────

std::string sign_license(const LicenseRecord& record, std::vector<uint8_t> ed25519_priv) {
    // 1. Canonical JSON payload.
    auto payload_json = to_json(record);

    // 2. Sign.
    std::span<const uint8_t> msg{reinterpret_cast<const uint8_t*>(payload_json.data()),
                                 payload_json.size()};
    auto sig = crypto::ed25519_sign(ed25519_priv, msg);

    // 3. Token = base64(payload_json) "." base64(sig)
    auto payload_bytes = std::span<const uint8_t>{
        reinterpret_cast<const uint8_t*>(payload_json.data()), payload_json.size()};

    return crypto::base64_encode(payload_bytes) + "." + crypto::base64_encode(sig);
}

// ──────────────────────────────────────────────
// Token: verify_license
// ──────────────────────────────────────────────

VerifyResult verify_license(const std::string& token, std::vector<uint8_t> ed25519_pub) {
    VerifyResult result;

    // 1. Split at ".".
    auto dot = token.rfind('.');
    if (dot == std::string::npos) {
        result.error = "invalid token format (no '.')";
        return result;
    }
    auto payload_b64 = token.substr(0, dot);
    auto sig_b64 = token.substr(dot + 1);

    // 2. Decode.
    crypto::Bytes payload_bytes, sig_bytes;
    try {
        payload_bytes = crypto::base64_decode(payload_b64);
        sig_bytes = crypto::base64_decode(sig_b64);
    } catch (const std::exception& e) {
        result.error = std::string("base64 decode failed: ") + e.what();
        return result;
    }

    // 3. Verify Ed25519 signature (constant-time inside OpenSSL).
    bool sig_ok = crypto::ed25519_verify(ed25519_pub, payload_bytes, sig_bytes);
    if (!sig_ok) {
        result.error = "signature verification failed";
        return result;
    }

    // 4. Parse payload.
    LicenseRecord rec;
    try {
        std::string payload_str(payload_bytes.begin(), payload_bytes.end());
        rec = record_from_json(payload_str);
    } catch (const std::exception& e) {
        result.error = std::string("payload parse failed: ") + e.what();
        return result;
    }

    // 5. Expiry check.
    if (rec.expires_at != 0) {
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
        if (static_cast<int64_t>(now) > rec.expires_at) {
            result.error = "license expired";
            return result;
        }
    }

    result.valid = true;
    result.record = rec;
    return result;
}

// ──────────────────────────────────────────────
// Anti-replay
// ──────────────────────────────────────────────

bool timestamp_is_fresh(int64_t req_timestamp, int64_t max_age_seconds) {
    auto now = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count());
    int64_t delta = now - req_timestamp;
    return delta >= 0 && delta <= max_age_seconds;
}

}  // namespace license
