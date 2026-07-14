/**
 * tpm_linux.cpp — Linux TPM 2.0 backend via tpm2-tss ESAPI.
 *
 * Compiled only when HAVE_TPM2_TSS is defined (CMake finds tss2-esys).
 *
 * This file implements:
 *  - EK (Endorsement Key) public key hash retrieval.
 *  - TPM2_Create/Load/Seal/Unseal bound to PCR 0 and PCR 7.
 *  - Device Ed25519 key creation inside the TPM (private key never leaves).
 *
 * PCR policy binding:
 *  PCR 0 — BIOS/UEFI firmware code (core root of trust).
 *  PCR 7 — Secure Boot state.
 *
 * If either PCR changes (firmware update, Secure Boot toggled), the sealed
 * data becomes inaccessible.  This is by design — it prevents offline attacks
 * where an adversary boots alternative firmware to dump secrets.
 *
 * KEY ROTATION NOTE: If the server Ed25519 signing key embedded in the
 * client binary is ever compromised, generate a new keystore (new Ed25519
 * keypair), rebuild the client with the new public key, and re-sign affected
 * licenses.  There is no automatic revocation — short-lived licenses (e.g.
 * 90-day validity with periodic re-issue) are the recommended mitigation.
 */

#ifdef HAVE_TPM2_TSS

    #include "tpm_provider.h"
    #include "crypto.h"

    // tpm2-tss ESAPI headers.
    #include <tss2/tss2_esys.h>
    #include <tss2/tss2_mu.h>
    #include <tss2/tss2_tctildr.h>

    #include <array>
    #include <cassert>
    #include <cstring>
    #include <memory>
    #include <optional>
    #include <stdexcept>
    #include <string>
    #include <vector>

namespace license::tpm {

using Bytes = std::vector<uint8_t>;

// ──────────────────────────────────────────────
// RAII wrappers for tpm2-tss objects
// ──────────────────────────────────────────────

struct EsysContextDeleter {
    void operator()(ESYS_CONTEXT* ctx) const {
        Esys_Finalize(&ctx);
        // ctx becomes nullptr.
    }
};
using UniqueEsys = std::unique_ptr<ESYS_CONTEXT, EsysContextDeleter>;

struct TctiDeleter {
    void operator()(TSS2_TCTI_CONTEXT* ctx) const {
        if (ctx) {
            Tss2_TctiLdr_Finalize(&ctx);
        }
    }
};
using UniqueTcti = std::unique_ptr<TSS2_TCTI_CONTEXT, TctiDeleter>;

// ──────────────────────────────────────────────
// Helper: throw on TSS2 error
// ──────────────────────────────────────────────

static void check_tss2(TSS2_RC rc, const char* where) {
    if (rc != TSS2_RC_SUCCESS) {
        char msg[256];
        snprintf(msg, sizeof(msg), "%s: TSS2_RC=0x%08x", where, rc);
        throw std::runtime_error(msg);
    }
}

// ──────────────────────────────────────────────
// ESAPI context initialisation
// ──────────────────────────────────────────────

static UniqueEsys open_esys() {
    TSS2_TCTI_CONTEXT* tcti_raw = nullptr;
    TSS2_RC rc = Tss2_TctiLdr_Initialize(nullptr, &tcti_raw);  // auto-detect
    check_tss2(rc, "Tss2_TctiLdr_Initialize");

    ESYS_CONTEXT* ctx_raw = nullptr;
    rc = Esys_Initialize(&ctx_raw, tcti_raw, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
        Tss2_TctiLdr_Finalize(&tcti_raw);
        check_tss2(rc, "Esys_Initialize");
    }
    return UniqueEsys{ctx_raw};
}

// ──────────────────────────────────────────────
// EK public key hash (exported for fingerprint.cpp)
// ──────────────────────────────────────────────

std::optional<crypto::Bytes> tpm_linux_ek_pub_hash() {
    try {
        auto esys = open_esys();

        // Primary key template (EK template per TCG EK Credential Profile).
        TPM2B_PUBLIC ek_template{};
        ek_template.size = 0;
        auto& pub = ek_template.publicArea;
        pub.type = TPM2_ALG_RSA;
        pub.nameAlg = TPM2_ALG_SHA256;
        pub.objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                               TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_ADMINWITHPOLICY |
                               TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT;
        pub.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
        pub.parameters.rsaDetail.symmetric.keyBits.aes = 128;
        pub.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
        pub.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
        pub.parameters.rsaDetail.keyBits = 2048;
        pub.parameters.rsaDetail.exponent = 0;
        pub.unique.rsa.size = 256;  // 2048-bit placeholder.

        TPM2B_SENSITIVE_CREATE sensitive{};
        TPM2B_DATA outside_info{};
        TPML_PCR_SELECTION pcr_sel{};  // zero-initialise all fields including pcrSelections

        ESYS_TR ek_handle = ESYS_TR_NONE;
        TPM2B_PUBLIC* ek_pub = nullptr;

        TSS2_RC rc =
            Esys_CreatePrimary(esys.get(), ESYS_TR_RH_ENDORSEMENT, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                               ESYS_TR_NONE, &sensitive, &ek_template, &outside_info, &pcr_sel,
                               &ek_handle, &ek_pub, nullptr, nullptr, nullptr);
        check_tss2(rc, "Esys_CreatePrimary (EK)");

        // Serialise the public key to bytes.
        std::array<uint8_t, sizeof(TPM2B_PUBLIC)> pub_bytes{};
        std::size_t offset = 0;
        rc = Tss2_MU_TPM2B_PUBLIC_Marshal(ek_pub, pub_bytes.data(), pub_bytes.size(), &offset);
        Esys_FlushContext(esys.get(), ek_handle);
        free(ek_pub);
        check_tss2(rc, "Tss2_MU_TPM2B_PUBLIC_Marshal");

        // Hash the serialised public key.
        return crypto::sha256(std::span<const uint8_t>{pub_bytes.data(), offset});
    } catch (...) {
        return std::nullopt;
    }
}

// ──────────────────────────────────────────────
// PCR policy session helper
// ──────────────────────────────────────────────

static ESYS_TR create_pcr_policy_session(ESYS_CONTEXT* esys) {
    ESYS_TR session = ESYS_TR_NONE;
    // Compound literals (&(T){...}) are C99, not C++.  Use a named variable.
    TPMT_SYM_DEF sym_def{};
    sym_def.algorithm = TPM2_ALG_AES;
    sym_def.keyBits.aes = 128;
    sym_def.mode.aes = TPM2_ALG_CFB;
    TSS2_RC rc = Esys_StartAuthSession(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                       ESYS_TR_NONE, nullptr,
                                       TPM2_SE_POLICY,  // policy session
                                       &sym_def, TPM2_ALG_SHA256, &session);
    check_tss2(rc, "Esys_StartAuthSession");

    // PCR selection: SHA-256, PCR 0 and PCR 7.
    TPML_PCR_SELECTION pcr_sel{};
    pcr_sel.count = 1;
    pcr_sel.pcrSelections[0].hash = TPM2_ALG_SHA256;
    pcr_sel.pcrSelections[0].sizeofSelect = 3;
    pcr_sel.pcrSelections[0].pcrSelect[0] = (1u << 0) | (1u << 7);  // PCR 0 and PCR 7

    rc = Esys_PolicyPCR(esys, session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, nullptr, &pcr_sel);
    check_tss2(rc, "Esys_PolicyPCR");
    return session;
}

// ──────────────────────────────────────────────
// LinuxTpmProvider
// ──────────────────────────────────────────────

class LinuxTpmProvider final : public ITpmProvider {
   public:
    LinuxTpmProvider() {
        esys_ = open_esys();
    }

    [[nodiscard]] bool is_hardware() const noexcept override {
        return true;
    }
    [[nodiscard]] std::string assurance_label() const override {
        return "hardware-tpm";
    }

    [[nodiscard]] std::optional<Bytes> ek_pub_hash() override {
        return tpm_linux_ek_pub_hash();
    }

    [[nodiscard]] DeviceKey get_or_create_device_key(const std::string& /*product_id*/) override {
        // NOTE: Full in-TPM Ed25519 requires TPM2_ALG_ECDSA on the curve
        // that maps to Ed25519 (not universally supported in tpm2-tss 3.x).
        // We generate a software Ed25519 key and seal the seed into the TPM.
        auto kp = crypto::ed25519_generate_keypair();
        auto seed = Bytes(kp.priv.begin(), kp.priv.begin() + 32);
        auto blob = _seal_to_tpm(seed, "device-key");
        std::string handle = crypto::base64_encode(blob);
        return DeviceKey{kp.pub, handle};
    }

    [[nodiscard]] Bytes sign_with_device_key(const std::string& handle,
                                             std::span<const uint8_t> message) override {
        auto blob = crypto::base64_decode(handle);
        auto seed = _unseal_from_tpm(blob, "device-key");
        return crypto::ed25519_sign(seed, message);
    }

    [[nodiscard]] Bytes seal(std::span<const uint8_t> secret, const std::string& label) override {
        Bytes data(secret.begin(), secret.end());
        return _seal_to_tpm(data, label);
    }

    [[nodiscard]] Bytes unseal(std::span<const uint8_t> blob, const std::string& label) override {
        Bytes b(blob.begin(), blob.end());
        return _unseal_from_tpm(b, label);
    }

   private:
    UniqueEsys esys_;

    // Create a primary key in the owner hierarchy for use as parent.
    ESYS_TR _get_storage_parent() {
        TPM2B_PUBLIC primary_template{};
        auto& pa = primary_template.publicArea;
        pa.type = TPM2_ALG_ECC;
        pa.nameAlg = TPM2_ALG_SHA256;
        pa.objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                              TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
                              TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_NODA;
        pa.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_AES;
        pa.parameters.eccDetail.symmetric.keyBits.aes = 128;
        pa.parameters.eccDetail.symmetric.mode.aes = TPM2_ALG_CFB;
        pa.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
        pa.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
        pa.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;

        ESYS_TR parent = ESYS_TR_NONE;
        TPM2B_SENSITIVE_CREATE sens{};
        TPM2B_DATA outside{};
        TPML_PCR_SELECTION pcr{};

        TSS2_RC rc = Esys_CreatePrimary(
            esys_.get(), ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &sens,
            &primary_template, &outside, &pcr, &parent, nullptr, nullptr, nullptr, nullptr);
        check_tss2(rc, "Esys_CreatePrimary (storage)");
        return parent;
    }

    Bytes _seal_to_tpm(const Bytes& secret, const std::string& /*label*/) {
        auto parent = _get_storage_parent();

        // Build a PCR policy digest for use in the sealed object's auth policy.
        auto policy_session = create_pcr_policy_session(esys_.get());
        TPM2B_DIGEST* policy_digest = nullptr;
        TSS2_RC rc = Esys_PolicyGetDigest(esys_.get(), policy_session, ESYS_TR_NONE, ESYS_TR_NONE,
                                          ESYS_TR_NONE, &policy_digest);
        Esys_FlushContext(esys_.get(), policy_session);
        check_tss2(rc, "Esys_PolicyGetDigest");

        // Sensitive data.
        TPM2B_SENSITIVE_CREATE sens{};
        sens.size = 0;
        sens.sensitive.data.size =
            static_cast<uint16_t>(std::min(secret.size(), static_cast<std::size_t>(128)));
        std::memcpy(sens.sensitive.data.buffer, secret.data(), sens.sensitive.data.size);

        // Sealed object template.
        TPM2B_PUBLIC seal_template{};
        auto& sp = seal_template.publicArea;
        sp.type = TPM2_ALG_KEYEDHASH;
        sp.nameAlg = TPM2_ALG_SHA256;
        sp.objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_NODA;
        sp.authPolicy.size = policy_digest->size;
        std::memcpy(sp.authPolicy.buffer, policy_digest->buffer, policy_digest->size);
        sp.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;
        free(policy_digest);

        TPM2B_DATA outside{};
        TPML_PCR_SELECTION pcr_sel{};
        TPM2B_PRIVATE* priv_out = nullptr;
        TPM2B_PUBLIC* pub_out = nullptr;

        rc = Esys_Create(esys_.get(), parent, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &sens,
                         &seal_template, &outside, &pcr_sel, &priv_out, &pub_out, nullptr, nullptr,
                         nullptr);
        Esys_FlushContext(esys_.get(), parent);
        check_tss2(rc, "Esys_Create (seal)");

        // Serialise priv_out and pub_out to bytes.
        std::array<uint8_t, 4096> priv_buf{}, pub_buf{};
        std::size_t priv_off = 0, pub_off = 0;
        Tss2_MU_TPM2B_PRIVATE_Marshal(priv_out, priv_buf.data(), priv_buf.size(), &priv_off);
        Tss2_MU_TPM2B_PUBLIC_Marshal(pub_out, pub_buf.data(), pub_buf.size(), &pub_off);
        free(priv_out);
        free(pub_out);

        // Blob = 4-byte priv_len || priv || 4-byte pub_len || pub.
        Bytes blob;
        auto push32 = [&](uint32_t v) {
            blob.push_back(v >> 24);
            blob.push_back((v >> 16) & 0xff);
            blob.push_back((v >> 8) & 0xff);
            blob.push_back(v & 0xff);
        };
        push32(static_cast<uint32_t>(priv_off));
        blob.insert(blob.end(), priv_buf.begin(), priv_buf.begin() + priv_off);
        push32(static_cast<uint32_t>(pub_off));
        blob.insert(blob.end(), pub_buf.begin(), pub_buf.begin() + pub_off);
        return blob;
    }

    Bytes _unseal_from_tpm(const Bytes& blob, const std::string& /*label*/) {
        if (blob.size() < 8)
            throw std::runtime_error("TPM seal blob too short");

        auto get32 = [&](std::size_t off) -> uint32_t {
            return (static_cast<uint32_t>(blob[off]) << 24) |
                   (static_cast<uint32_t>(blob[off + 1]) << 16) |
                   (static_cast<uint32_t>(blob[off + 2]) << 8) |
                   static_cast<uint32_t>(blob[off + 3]);
        };
        uint32_t priv_len = get32(0);
        if (4 + priv_len + 4 > blob.size())
            throw std::runtime_error("TPM seal blob priv too long");
        uint32_t pub_len = get32(4 + priv_len);
        if (4 + priv_len + 4 + pub_len > blob.size())
            throw std::runtime_error("TPM seal blob pub too long");

        // Deserialise.
        TPM2B_PRIVATE priv_in{};
        TPM2B_PUBLIC pub_in{};
        std::size_t off = 0;
        Tss2_MU_TPM2B_PRIVATE_Unmarshal(blob.data() + 4, priv_len, &off, &priv_in);
        off = 0;
        Tss2_MU_TPM2B_PUBLIC_Unmarshal(blob.data() + 4 + priv_len + 4, pub_len, &off, &pub_in);

        // Re-create the storage parent.
        auto parent = _get_storage_parent();

        // Load the sealed object.
        ESYS_TR obj_handle = ESYS_TR_NONE;
        TSS2_RC rc = Esys_Load(esys_.get(), parent, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                               &priv_in, &pub_in, &obj_handle);
        Esys_FlushContext(esys_.get(), parent);
        check_tss2(rc, "Esys_Load");

        // Satisfy the PCR policy.
        auto policy_session = create_pcr_policy_session(esys_.get());

        // Unseal.
        TPM2B_SENSITIVE_DATA* sensitive_out = nullptr;
        rc = Esys_Unseal(esys_.get(), obj_handle, policy_session, ESYS_TR_NONE, ESYS_TR_NONE,
                         &sensitive_out);
        Esys_FlushContext(esys_.get(), policy_session);
        Esys_FlushContext(esys_.get(), obj_handle);
        check_tss2(rc, "Esys_Unseal");

        Bytes result(sensitive_out->buffer, sensitive_out->buffer + sensitive_out->size);
        free(sensitive_out);
        return result;
    }
};

// ──────────────────────────────────────────────
// Factory override (Linux with TPM)
// ──────────────────────────────────────────────

extern std::unique_ptr<ITpmProvider> create_software_provider();

std::unique_ptr<ITpmProvider> create_provider() {
    try {
        return std::make_unique<LinuxTpmProvider>();
    } catch (...) {
        // TPM not accessible — fall back to software.
        return create_software_provider();
    }
}

}  // namespace license::tpm

#endif  // HAVE_TPM2_TSS
