#pragma once

/**
 * tpm_provider.h — TPM abstraction interface.
 *
 * ITpmProvider abstracts over:
 *  - Linux: tpm2-tss ESAPI (TSS2_ESYS)
 *  - Windows: TBS API (tbsapi.h)
 *  - Software fallback: OS keyring (DPAPI / libsecret)
 *
 * Implementations live in:
 *   tpm_linux.cpp    (compiled with HAVE_TPM2_TSS)
 *   tpm_windows.cpp  (compiled on WIN32 with HAVE_TBS)
 *   tpm_software.cpp (always compiled, used when hardware TPM absent)
 */

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace license::tpm {

using Bytes = std::vector<uint8_t>;

// ──────────────────────────────────────────────
// PCR policy
// ──────────────────────────────────────────────

/// PCR indices used in the sealing policy.
/// PCR 0: BIOS/UEFI firmware
/// PCR 7: Secure Boot state
/// PCR 11: BitLocker / measured boot (Windows)
static constexpr uint32_t SEAL_PCR_MASK = (1u << 0) | (1u << 7);

// ──────────────────────────────────────────────
// Interface
// ──────────────────────────────────────────────

class ITpmProvider {
   public:
    virtual ~ITpmProvider() = default;

    /// Is this a hardware TPM backend?
    [[nodiscard]] virtual bool is_hardware() const noexcept = 0;

    /// Assurance label: "hardware-tpm" | "software-dpapi" | "software-keyring"
    [[nodiscard]] virtual std::string assurance_label() const = 0;

    // ── EK (Endorsement Key) ─────────────────

    /**
     * Return the SHA-256 of the TPM EK public key (hardware only).
     * Software implementations return nullopt.
     */
    [[nodiscard]] virtual std::optional<Bytes> ek_pub_hash() = 0;

    // ── Device keypair (seal/unseal) ─────────

    /**
     * Generate (or load from sealed storage) the device Ed25519 keypair.
     *
     * On hardware TPM: the private key is created inside the TPM and
     * never leaves it in plaintext.  Operations go through the TPM.
     * On software fallback: a software Ed25519 key is generated and
     * stored in the OS keyring / DPAPI-encrypted file.
     *
     * Returns { pub_key_bytes, opaque_handle } where opaque_handle is
     * a platform-specific reference used by sign_with_device_key().
     */
    struct DeviceKey {
        Bytes pub;           // 32-byte Ed25519 public key
        std::string handle;  // opaque serialised handle / key ID
    };
    [[nodiscard]] virtual DeviceKey get_or_create_device_key(const std::string& product_id) = 0;

    /**
     * Sign `message` using the device private key referenced by `handle`.
     * Returns 64-byte Ed25519 signature.
     */
    [[nodiscard]] virtual Bytes sign_with_device_key(const std::string& handle,
                                                     std::span<const uint8_t> message) = 0;

    // ── Sealing / Unsealing ──────────────────

    /**
     * Seal `secret` to the current machine's TPM PCR state.
     * On software fallback: encrypt with OS keyring / DPAPI.
     *
     * Returns an opaque blob that can be stored on disk.
     * The blob cannot be unsealed on a different machine or (hardware TPM)
     * after significant firmware/OS changes (PCR values drift).
     */
    [[nodiscard]] virtual Bytes seal(std::span<const uint8_t> secret, const std::string& label) = 0;

    /**
     * Unseal a blob previously produced by seal().
     * Throws std::runtime_error if PCR policy fails or blob is corrupt.
     */
    [[nodiscard]] virtual Bytes unseal(std::span<const uint8_t> blob, const std::string& label) = 0;
};

// ──────────────────────────────────────────────
// Factory
// ──────────────────────────────────────────────

/**
 * Create the best available TPM provider for the current platform.
 * Order of preference:
 *   1. Hardware TPM (Linux ESAPI / Windows TBS)
 *   2. Software fallback (DPAPI / libsecret)
 */
[[nodiscard]] std::unique_ptr<ITpmProvider> create_provider();

}  // namespace license::tpm
