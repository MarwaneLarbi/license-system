/**
 * license_client.cpp — liblicenseclient implementation.
 *
 * Server public keys are loaded at runtime from server_pubkeys.json;
 * there are no compiled-in key constants.
 */

#include "license_client.h"
#include "crypto.h"
#include "fingerprint.h"
#include "license.h"
#include "tpm_provider.h"

#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

// chmod(2) — file permission hardening.
#include <sys/stat.h>

namespace fs = std::filesystem;
using namespace license;

namespace license::client {

using json = nlohmann::json;
using crypto::Bytes;

// ──────────────────────────────────────────────
// load_server_keys
// ──────────────────────────────────────────────

ServerKeys load_server_keys(const std::string& config_path) {
    std::ifstream f(config_path);
    if (!f)
        throw std::runtime_error("Cannot open server key config: " + config_path +
                                 "\nRun: license-server init-keys --keystore <path> --pub-out " +
                                 config_path);

    json j;
    try {
        f >> j;
    } catch (const std::exception& e) {
        throw std::runtime_error("Malformed server_pubkeys.json: " + std::string(e.what()));
    }

    ServerKeys keys;
    try {
        keys.x25519_pub = crypto::base64_decode(j.at("server_x25519_pub").get<std::string>());
        keys.ed25519_pub = crypto::base64_decode(j.at("server_ed25519_pub").get<std::string>());
    } catch (const std::exception& e) {
        throw std::runtime_error("Invalid keys in server_pubkeys.json: " + std::string(e.what()));
    }

    if (keys.x25519_pub.size() != 32)
        throw std::runtime_error("server_x25519_pub must be 32 bytes");
    if (keys.ed25519_pub.size() != 32)
        throw std::runtime_error("server_ed25519_pub must be 32 bytes");

    return keys;
}

// ──────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────

namespace {

fs::path license_store_dir() {
#ifdef _WIN32
    const char* appdata = std::getenv("APPDATA");
    return fs::path(appdata ? appdata : ".") / "license-system" / "client";
#else
    const char* home = std::getenv("HOME");
    return fs::path(home ? home : ".") / ".config" / "license-system" / "client";
#endif
}

fs::path sealed_license_path(const std::string& product_id) {
    return license_store_dir() / (product_id + ".lic");
}

void ensure_dir(const fs::path& p) {
    fs::create_directories(p);
#ifndef _WIN32
    ::chmod(p.c_str(), 0700);
#endif
}

void write_protected(const fs::path& p, const Bytes& data) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!f)
        throw std::runtime_error("Cannot write: " + p.string());
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
#ifndef _WIN32
    ::chmod(p.c_str(), 0600);
#endif
}

Bytes read_protected(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f)
        throw std::runtime_error("Cannot read: " + p.string());
    return Bytes(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

Bytes make_aad(const std::string& product_id) {
    std::string s = product_id + "|license-client-v" LICENSE_SYSTEM_VERSION;
    return Bytes(s.begin(), s.end());
}

}  // anonymous namespace

// ──────────────────────────────────────────────
// generate_request
// ──────────────────────────────────────────────

GenerateRequestResult generate_request(const std::string& product_id,
                                       const std::string& customer_hint, const ServerKeys& keys) {
    GenerateRequestResult result;
    try {
        // 1. Collect fingerprint.
        auto fp = fingerprint::compute(/*use_tpm=*/true);

        // 2. Get or create device keypair via TPM provider.
        auto tpm = tpm::create_provider();
        auto dkey = tpm->get_or_create_device_key(product_id);

        // 3. Build request payload.
        LicenseRequest req;
        req.product_id = product_id;
        req.customer_hint = customer_hint;
        req.fingerprint_hash = fp.hash;
        req.fingerprint_assurance = fp.assurance_level;
        req.device_pubkey_b64 = crypto::base64_encode(dkey.pub);
        req.timestamp =
            static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                     std::chrono::system_clock::now().time_since_epoch())
                                     .count());
        req.nonce = crypto::base64_encode(crypto::random_bytes(16));

        auto req_json = to_json(req);

        // 4. Hybrid-encrypt to server X25519 public key (from JSON config).
        auto aad = make_aad(product_id);
        Bytes req_bytes(req_json.begin(), req_json.end());
        auto encrypted = crypto::hybrid_encrypt(keys.x25519_pub, aad, req_bytes);

        result.blob_b64 = crypto::base64_encode(encrypted);
        result.fingerprint_hash = fp.hash;
        result.fingerprint_assurance = fp.assurance_level;
        result.success = true;
    } catch (const std::exception& e) {
        result.error = e.what();
    }
    return result;
}

// ──────────────────────────────────────────────
// activate
// ──────────────────────────────────────────────

ActivateResult activate(const std::string& token_b64, const ServerKeys& keys) {
    ActivateResult result;
    try {
        // 1. Verify the signed license token against the runtime-loaded ed25519 key.
        auto vr = verify_license(token_b64, keys.ed25519_pub);
        if (!vr.valid) {
            result.error = vr.error;
            return result;
        }

        // 2. Verify fingerprint matches this machine.
        if (!fingerprint::verify(vr.record.fingerprint_hash)) {
            result.error = "fingerprint mismatch — license is not valid for this machine";
            return result;
        }

        // 3. Seal the token into TPM-protected storage.
        ensure_dir(license_store_dir());
        auto tpm = tpm::create_provider();
        auto seal_label = "license-" + vr.record.product_id;
        Bytes token_bytes(token_b64.begin(), token_b64.end());
        auto blob = tpm->seal(token_bytes, seal_label);

        write_protected(sealed_license_path(vr.record.product_id), blob);

        result.success = true;
        result.license_id = vr.record.license_id;
        result.product_id = vr.record.product_id;
    } catch (const std::exception& e) {
        result.error = e.what();
    }
    return result;
}

// ──────────────────────────────────────────────
// verify_at_startup
// ──────────────────────────────────────────────

VerifyResult verify_at_startup(const std::string& product_id, const ServerKeys& keys) {
    VerifyResult result;
    try {
        // 1. Read sealed blob from disk.
        auto path = sealed_license_path(product_id);
        if (!fs::exists(path)) {
            result.error = "no license found for product: " + product_id;
            return result;
        }
        auto blob = read_protected(path);

        // 2. Unseal via TPM provider.
        auto tpm = tpm::create_provider();
        auto seal_label = "license-" + product_id;
        Bytes token_bytes;
        try {
            token_bytes = tpm->unseal(blob, seal_label);
        } catch (const std::exception& e) {
            result.error =
                std::string("license unseal failed (PCR policy violation or corrupt blob): ") +
                e.what();
            return result;
        }
        std::string token_b64(token_bytes.begin(), token_bytes.end());

        // 3. Re-verify signature and expiry.
        auto vr = verify_license(token_b64, keys.ed25519_pub);
        if (!vr.valid) {
            result.error = vr.error;
            return result;
        }

        // 4. Re-verify fingerprint.
        if (!fingerprint::verify(vr.record.fingerprint_hash)) {
            result.error = "fingerprint mismatch — hardware may have changed";
            return result;
        }

        result.valid = true;
        result.license_id = vr.record.license_id;
        result.product_id = vr.record.product_id;
        result.assurance_level = vr.record.fingerprint_assurance;
        result.expires_at = vr.record.expires_at;
        result.issued_at = vr.record.issued_at;
        result.features = vr.record.features;
    } catch (const std::exception& e) {
        result.error = e.what();
    }
    return result;
}

// ──────────────────────────────────────────────
// deactivate
// ──────────────────────────────────────────────

bool deactivate(const std::string& product_id) {
    try {
        auto path = sealed_license_path(product_id);
        if (fs::exists(path)) {
            // Overwrite with random bytes before deleting.
            auto size = fs::file_size(path);
            auto rnd = crypto::random_bytes(size);
            write_protected(path, rnd);
            fs::remove(path);
        }
        return true;
    } catch (...) {
        return false;
    }
}

}  // namespace license::client
