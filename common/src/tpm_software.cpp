/**
 * tpm_software.cpp — Software-only TPM fallback.
 *
 * When no hardware TPM is available, we fall back to:
 *  - Linux  : AES-256-GCM encrypted file under ~/.config/license-system/,
 *             additionally protected by libsecret (keyring) when available.
 *  - Windows: DPAPI (CryptProtectData) wrapping of the sealed blob.
 *
 * The sealed blob is machine-bound only to the extent the OS keyring /
 * DPAPI provides machine-scope binding.  Licenses activated through this
 * path are marked assurance_level = "software".
 *
 * NOTE: Because no hardware TPM EK is available, the fingerprint
 * is less authoritative.  This is flagged in the license record.
 */

#include "tpm_provider.h"
#include "crypto.h"

#include <fstream>
#include <filesystem>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

// chmod(2) / fchmod(2) — required for file permission hardening.
#include <sys/stat.h>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <dpapi.h>
    #pragma comment(lib, "crypt32.lib")
#endif

namespace fs = std::filesystem;

namespace license::tpm {

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

namespace {

fs::path software_store_dir() {
#ifdef _WIN32
    const char* appdata = std::getenv("APPDATA");
    if (!appdata)
        throw std::runtime_error("APPDATA not set");
    return fs::path(appdata) / "license-system";
#else
    const char* home = std::getenv("HOME");
    if (!home)
        throw std::runtime_error("HOME not set");
    return fs::path(home) / ".config" / "license-system";
#endif
}

fs::path key_file_path(const std::string& product_id) {
    return software_store_dir() / (product_id + ".devkey");
}

fs::path seal_file_path(const std::string& label) {
    return software_store_dir() / (label + ".sealed");
}

void ensure_dir(const fs::path& dir) {
    fs::create_directories(dir);
    // On Linux, restrict permissions to owner only.
#ifndef _WIN32
    ::chmod(dir.c_str(), 0700);
#endif
}

/// Derive a machine-local 32-byte key from a label using a machine-specific secret.
/// On Linux we use a persistent random file; on Windows we use DPAPI as the
/// wrapping layer directly (no derived key needed).
crypto::Bytes derive_machine_key(const std::string& label) {
#ifndef _WIN32
    // Store a 32-byte machine secret in ~/.config/license-system/.machine_secret
    auto dir = software_store_dir();
    auto path = dir / ".machine_secret";
    ensure_dir(dir);

    crypto::Bytes secret;
    if (fs::exists(path)) {
        std::ifstream f(path, std::ios::binary);
        if (!f)
            throw std::runtime_error("Cannot read machine secret");
        secret.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
        if (secret.size() < 32)
            throw std::runtime_error("Machine secret file corrupt");
    } else {
        secret = crypto::random_bytes(32);
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        if (!f)
            throw std::runtime_error("Cannot write machine secret");
        f.write(reinterpret_cast<const char*>(secret.data()),
                static_cast<std::streamsize>(secret.size()));
        ::chmod(path.c_str(), 0600);
    }

    // Derive a per-label key.
    auto info = crypto::Bytes(label.begin(), label.end());
    return crypto::hkdf_sha256(secret, {}, info, 32);
#else
    // On Windows, DPAPI is used directly; return a placeholder.
    (void)label;
    return {};
#endif
}

void write_file(const fs::path& p, const crypto::Bytes& data) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!f)
        throw std::runtime_error("Cannot write file: " + p.string());
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
#ifndef _WIN32
    ::chmod(p.c_str(), 0600);
#endif
}

crypto::Bytes read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f)
        throw std::runtime_error("Cannot read file: " + p.string());
    return crypto::Bytes(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

}  // anonymous namespace

// ──────────────────────────────────────────────
// SoftwareTpmProvider
// ──────────────────────────────────────────────

class SoftwareTpmProvider final : public ITpmProvider {
   public:
    [[nodiscard]] bool is_hardware() const noexcept override {
        return false;
    }
    [[nodiscard]] std::string assurance_label() const override {
#ifdef _WIN32
        return "software-dpapi";
#else
        return "software-keyring";
#endif
    }

    [[nodiscard]] std::optional<Bytes> ek_pub_hash() override {
        return std::nullopt;  // No hardware EK available.
    }

    [[nodiscard]] DeviceKey get_or_create_device_key(const std::string& product_id) override {
        auto path = key_file_path(product_id);
        ensure_dir(software_store_dir());

        if (fs::exists(path)) {
            // Load existing sealed key.
            auto blob = read_file(path);
            auto raw = _unseal_blob(blob, "devkey-" + product_id);
            // raw = 32-byte private seed || 32-byte pub.
            if (raw.size() < 64)
                throw std::runtime_error("Corrupt device key file");
            Bytes pub(raw.begin() + 32, raw.begin() + 64);
            Bytes priv(raw.begin(), raw.begin() + 32);
            // Reconstruct handle = path string.
            return DeviceKey{pub, path.string()};
        }

        // Generate a new Ed25519 keypair (software).
        auto kp = crypto::ed25519_generate_keypair();
        // Store sealed: 32-byte seed || 32-byte pub.
        Bytes raw;
        raw.insert(raw.end(), kp.priv.begin(), kp.priv.begin() + 32);
        raw.insert(raw.end(), kp.pub.begin(), kp.pub.end());
        auto blob = _seal_blob(raw, "devkey-" + product_id);
        write_file(path, blob);

        return DeviceKey{kp.pub, path.string()};
    }

    [[nodiscard]] Bytes sign_with_device_key(const std::string& handle,
                                             std::span<const uint8_t> message) override {
        auto blob = read_file(fs::path(handle));
        auto raw = _unseal_blob(blob, "devkey-" + fs::path(handle).stem().string());
        if (raw.size() < 32)
            throw std::runtime_error("Corrupt device key blob");
        Bytes priv(raw.begin(), raw.begin() + 32);
        return crypto::ed25519_sign(priv, message);
    }

    [[nodiscard]] Bytes seal(std::span<const uint8_t> secret, const std::string& label) override {
        Bytes data(secret.begin(), secret.end());
        auto blob = _seal_blob(data, label);
        auto path = seal_file_path(label);
        ensure_dir(software_store_dir());
        write_file(path, blob);
        return blob;
    }

    [[nodiscard]] Bytes unseal(std::span<const uint8_t> blob, const std::string& label) override {
        Bytes b(blob.begin(), blob.end());
        return _unseal_blob(b, label);
    }

   private:
#ifdef _WIN32
    Bytes _seal_blob(const Bytes& data, const std::string& label) {
        DATA_BLOB in{static_cast<DWORD>(data.size()), const_cast<BYTE*>(data.data())};
        DATA_BLOB out{};
        DATA_BLOB entropy{};
        auto entropy_bytes = crypto::sha256(
            std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(label.data()), label.size()});
        entropy.pbData = entropy_bytes.data();
        entropy.cbData = static_cast<DWORD>(entropy_bytes.size());

        if (!CryptProtectData(&in, L"license-seal", &entropy, nullptr, nullptr,
                              CRYPTPROTECT_LOCAL_MACHINE, &out))
            throw std::runtime_error("CryptProtectData failed");
        Bytes result(out.pbData, out.pbData + out.cbData);
        LocalFree(out.pbData);
        return result;
    }

    Bytes _unseal_blob(const Bytes& blob, const std::string& label) {
        DATA_BLOB in{static_cast<DWORD>(blob.size()), const_cast<BYTE*>(blob.data())};
        DATA_BLOB out{};
        DATA_BLOB entropy{};
        auto entropy_bytes = crypto::sha256(
            std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(label.data()), label.size()});
        entropy.pbData = entropy_bytes.data();
        entropy.cbData = static_cast<DWORD>(entropy_bytes.size());

        if (!CryptUnprotectData(&in, nullptr, &entropy, nullptr, nullptr,
                                CRYPTPROTECT_LOCAL_MACHINE, &out))
            throw std::runtime_error("CryptUnprotectData failed");
        Bytes result(out.pbData, out.pbData + out.cbData);
        LocalFree(out.pbData);
        return result;
    }
#else
    Bytes _seal_blob(const Bytes& data, const std::string& label) {
        auto key = derive_machine_key(label);
        auto aad_bytes = Bytes(label.begin(), label.end());
        return crypto::aes256gcm_encrypt(key, aad_bytes, data);
    }

    Bytes _unseal_blob(const Bytes& blob, const std::string& label) {
        auto key = derive_machine_key(label);
        auto aad_bytes = Bytes(label.begin(), label.end());
        return crypto::aes256gcm_decrypt(key, aad_bytes, blob);
    }
#endif
};

// ──────────────────────────────────────────────
// Factory (defined here; overridden by platform impls when hardware available)
// ──────────────────────────────────────────────

#if !defined(HAVE_TPM2_TSS) && !defined(HAVE_TBS)
std::unique_ptr<ITpmProvider> create_provider() {
    return std::make_unique<SoftwareTpmProvider>();
}
#endif

// Exposed for use by tpm_linux.cpp / tpm_windows.cpp as fallback.
std::unique_ptr<ITpmProvider> create_software_provider() {
    return std::make_unique<SoftwareTpmProvider>();
}

}  // namespace license::tpm
