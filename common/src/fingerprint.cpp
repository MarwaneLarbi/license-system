/**
 * fingerprint.cpp — Hardware fingerprint collection.
 *
 * Platform support:
 *  - Linux  : /sys/class/dmi/id/ for SMBIOS, /proc/cpuinfo, udev for disk serial
 *  - Windows: GetSystemFirmwareTable (SMBIOS), __cpuid, SetupAPI for disk serial
 *
 * The fingerprint is stable across reboots but may change with:
 *  - Motherboard replacement
 *  - Primary disk replacement
 *  - BIOS/UEFI settings that change the SMBIOS UUID
 */

#include "fingerprint.h"
#include "crypto.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <intrin.h>
    #include <setupapi.h>
    #pragma comment(lib, "setupapi.lib")
#else
    // <cpuid.h> only exists on x86/x86-64; omit it on ARM/RISC-V/etc.
    #if defined(__x86_64__) || defined(__i386__)
        #include <cpuid.h>
    #endif
    #include <fcntl.h>
    #include <sys/ioctl.h>
    #include <unistd.h>
    #ifdef __linux__
        #include <linux/hdreg.h>
        #include <scsi/sg.h>
    #endif
#endif

namespace license::fingerprint {

// ──────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────

namespace {

std::string to_hex(const crypto::Bytes& bytes) {
    std::ostringstream oss;
    for (auto b : bytes)
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return oss.str();
}

/// Read a single line from a sysfs file, trimmed.
#ifdef __linux__
std::string read_sysfs(const char* path) {
    std::ifstream f(path);
    if (!f.is_open())
        return {};
    std::string line;
    std::getline(f, line);
    // Trim trailing whitespace.
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' '))
        line.pop_back();
    return line;
}
#endif

/// Encode a 32-bit big-endian length prefix into dst.
void write_len32(std::vector<uint8_t>& dst, uint32_t len) {
    dst.push_back(static_cast<uint8_t>((len >> 24) & 0xff));
    dst.push_back(static_cast<uint8_t>((len >> 16) & 0xff));
    dst.push_back(static_cast<uint8_t>((len >> 8) & 0xff));
    dst.push_back(static_cast<uint8_t>((len)&0xff));
}

/// Append a length-prefixed string component.
void append_component(std::vector<uint8_t>& buf, const std::string& s) {
    write_len32(buf, static_cast<uint32_t>(s.size()));
    buf.insert(buf.end(), s.begin(), s.end());
}

}  // anonymous namespace

// ──────────────────────────────────────────────
// SMBIOS UUID
// ──────────────────────────────────────────────

std::string smbios_uuid() {
#ifdef __linux__
    // /sys/class/dmi/id/product_uuid  (requires root or kernel ≥ 5.x group perm)
    auto uuid = read_sysfs("/sys/class/dmi/id/product_uuid");
    if (!uuid.empty())
        return uuid;
    // Fallback: try /sys/class/dmi/id/board_serial
    return read_sysfs("/sys/class/dmi/id/board_serial");
#elif defined(_WIN32)
    // GetSystemFirmwareTable("RSMB", 0) returns the raw SMBIOS table.
    DWORD size = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
    if (size == 0)
        return {};
    std::vector<uint8_t> buf(size);
    if (GetSystemFirmwareTable('RSMB', 0, buf.data(), size) != size)
        return {};

    // Raw SMBIOS header: 8-byte header, then SMBIOS structures.
    // Structure type 1 (System Information) has UUID at offset 8 (16 bytes).
    std::size_t off = 8;  // skip RawSMBIOSData header (4 bytes used, 4 bytes table len)
    // Actually the structure starts at buf[8] for RawSMBIOSData.
    // TableLength is at buf[4..7].
    if (size < 32)
        return {};
    // Search for type-1 structure.
    std::size_t table_start = 8;
    std::size_t table_end = table_start + size - 8;
    off = table_start;
    while (off + 4 < table_end) {
        uint8_t type = buf[off];
        uint8_t length = buf[off + 1];
        if (type == 127)
            break;  // end-of-table
        if (type == 1 && length >= 25) {
            // UUID is at offset 8 within the structure.
            const uint8_t* u = &buf[off + 8];
            // RFC 4122 little-endian fields (SMBIOS 2.6+).
            char uuid_str[37];
            snprintf(uuid_str, sizeof(uuid_str),
                     "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
                     "%02x%02x%02x%02x%02x%02x",
                     u[3], u[2], u[1], u[0], u[5], u[4], u[7], u[6], u[8], u[9], u[10], u[11],
                     u[12], u[13], u[14], u[15]);
            return uuid_str;
        }
        // Skip to next structure: formatted area (length bytes) + string area.
        off += length;
        while (off + 1 < table_end && !(buf[off] == 0 && buf[off + 1] == 0))
            ++off;
        off += 2;
    }
    return {};
#else
    return {};
#endif
}

// ──────────────────────────────────────────────
// CPU identifier
// ──────────────────────────────────────────────

std::string cpu_id() {
    // CPUID is an x86/x86-64 instruction; on other architectures we return a
    // placeholder derived from /proc/cpuinfo or simply "unknown-cpu".
#if defined(_WIN32)
    // Windows x86/x64: use the MSVC intrinsic __cpuid.
    std::array<uint32_t, 12> brand{};
    std::array<int, 4> regs{};
    __cpuid(regs.data(), 0x80000000u);
    uint32_t max_ext = static_cast<uint32_t>(regs[0]);
    if (max_ext >= 0x80000004u) {
        for (int leaf = 2; leaf <= 4; ++leaf) {
            __cpuid(regs.data(), 0x80000000u + leaf);
            std::memcpy(&brand[(leaf - 2) * 4], regs.data(), 16);
        }
    }
    auto* chars = reinterpret_cast<char*>(brand.data());
    std::string result(chars, 48);
    auto pos = result.find_last_not_of(' ');
    if (pos != std::string::npos)
        result = result.substr(0, pos + 1);
    __cpuid(regs.data(), 1);
    {
        char hex[16];
        snprintf(hex, sizeof(hex), "-%08X", static_cast<uint32_t>(regs[0]));
        result += hex;
    }
    return result;
#elif defined(__x86_64__) || defined(__i386__)
    // Linux/macOS x86: use <cpuid.h> GCC built-in __get_cpuid.
    std::array<uint32_t, 12> brand{};
    unsigned a, b, c, d;
    if (__get_cpuid(0x80000000u, &a, &b, &c, &d) && a >= 0x80000004u) {
        for (int leaf = 2; leaf <= 4; ++leaf) {
            __get_cpuid(0x80000000u + leaf, &a, &b, &c, &d);
            brand[(leaf - 2) * 4 + 0] = a;
            brand[(leaf - 2) * 4 + 1] = b;
            brand[(leaf - 2) * 4 + 2] = c;
            brand[(leaf - 2) * 4 + 3] = d;
        }
    }
    auto* chars = reinterpret_cast<char*>(brand.data());
    std::string result(chars, 48);
    auto pos = result.find_last_not_of(' ');
    if (pos != std::string::npos)
        result = result.substr(0, pos + 1);
    if (__get_cpuid(1, &a, &b, &c, &d)) {
        char hex[16];
        snprintf(hex, sizeof(hex), "-%08X", a);
        result += hex;
    }
    return result;
#elif defined(__linux__)
    // Non-x86 Linux: read the CPU model from /proc/cpuinfo.
    std::ifstream f("/proc/cpuinfo");
    std::string line;
    while (std::getline(f, line)) {
        // ARM: "CPU part", RISC-V: "processor", generic: "model name"
        for (const char* key : {"model name", "CPU part", "Hardware"}) {
            if (line.rfind(key, 0) != std::string::npos) {
                auto colon = line.find(':');
                if (colon != std::string::npos) {
                    auto val = line.substr(colon + 1);
                    // trim leading spaces
                    auto start = val.find_first_not_of(' ');
                    return start == std::string::npos ? "unknown-cpu" : val.substr(start);
                }
            }
        }
    }
    return "unknown-cpu";
#else
    return "unknown-cpu";
#endif
}

// ──────────────────────────────────────────────
// Primary disk serial number
// ──────────────────────────────────────────────

std::string primary_disk_serial() {
#ifdef __linux__
    // Try /sys/class/block/sda/device/serial or nvme equivalent.
    for (const char* path :
         {"/sys/class/block/nvme0n1/device/serial", "/sys/class/block/sda/device/serial",
          "/sys/block/nvme0n1/device/serial", "/sys/block/sda/device/serial"}) {
        auto s = read_sysfs(path);
        if (!s.empty())
            return s;
    }
    return {};
#elif defined(_WIN32)
    // Use SetupAPI to enumerate disk drives and get their serial numbers.
    HDEVINFO dev_info =
        SetupDiGetClassDevs(&GUID_DEVCLASS_DISKDRIVE, nullptr, nullptr, DIGCF_PRESENT);
    if (dev_info == INVALID_HANDLE_VALUE)
        return {};

    SP_DEVINFO_DATA dev_data{};
    dev_data.cbSize = sizeof(SP_DEVINFO_DATA);
    std::string serial;
    if (SetupDiEnumDeviceInfo(dev_info, 0, &dev_data)) {
        char buf[256]{};
        DWORD size = 0;
        SetupDiGetDeviceRegistryPropertyA(dev_info, &dev_data, SPDRP_HARDWAREID, nullptr,
                                          reinterpret_cast<BYTE*>(buf), sizeof(buf), &size);
        serial = buf;
    }
    SetupDiDestroyDeviceInfoList(dev_info);
    return serial;
#else
    return {};
#endif
}

// ──────────────────────────────────────────────
// TPM EK hash (delegates to TPM provider)
// ──────────────────────────────────────────────

std::optional<std::string> tpm_ek_hash() {
    // We lazily attempt to create the TPM provider here for fingerprinting.
    // Full TPM integration is in tpm_provider.h / tpm_*.cpp.
    // For fingerprinting we only need the EK public key hash.
    // Return nullopt if no hardware TPM is available.
#ifdef HAVE_TPM2_TSS
    try {
        // Dynamically query ESAPI for EK without going through our full provider.
        // For simplicity we rely on the fingerprint module's provider indirection.
        // Actual implementation is in tpm_linux.cpp::ek_pub_hash_impl().
        extern std::optional<crypto::Bytes> tpm_linux_ek_pub_hash();
        auto hash = tpm_linux_ek_pub_hash();
        if (hash)
            return to_hex(*hash);
    } catch (...) {
    }
#endif
#ifdef HAVE_TBS
    try {
        extern std::optional<crypto::Bytes> tpm_windows_ek_pub_hash();
        auto hash = tpm_windows_ek_pub_hash();
        if (hash)
            return to_hex(*hash);
    } catch (...) {
    }
#endif
    return std::nullopt;
}

// ──────────────────────────────────────────────
// Composite fingerprint
// ──────────────────────────────────────────────

FingerprintResult compute(bool use_tpm) {
    FingerprintResult result;

    // Collect components.
    std::optional<std::string> ek;
    if (use_tpm)
        ek = tpm_ek_hash();

    std::string uuid = smbios_uuid();
    std::string cpu = cpu_id();
    std::string disk = primary_disk_serial();

    // Build canonical input buffer:
    //   "LFPV1" || len32(tpm_ek) || tpm_ek
    //           || len32(uuid)   || uuid
    //           || len32(cpu)    || cpu
    //           || len32(disk)   || disk
    std::vector<uint8_t> buf;
    const std::string prefix = "LFPV1";
    buf.insert(buf.end(), prefix.begin(), prefix.end());

    std::string ek_str = ek.value_or("");
    append_component(buf, ek_str);
    append_component(buf, uuid);
    append_component(buf, cpu);
    append_component(buf, disk);

    // SHA-256.
    auto digest = crypto::sha256(buf);
    result.hash = to_hex(digest);

    result.tpm_bound = ek.has_value();
    result.assurance_level = result.tpm_bound ? "hardware" : "software";

    if (!ek_str.empty())
        result.components.push_back("tpm_ek:" + ek_str.substr(0, 16) + "...");
    if (!uuid.empty())
        result.components.push_back("bios_uuid:" + uuid);
    if (!cpu.empty())
        result.components.push_back("cpu:" + cpu);
    if (!disk.empty())
        result.components.push_back("disk:" + disk);

    return result;
}

bool verify(const std::string& expected_hash, bool use_tpm) {
    auto current = compute(use_tpm);
    // Constant-time hex string comparison via byte-level ct_equal.
    auto to_bytes = [](const std::string& s) -> crypto::Bytes {
        return crypto::Bytes(s.begin(), s.end());
    };
    return crypto::ct_equal(to_bytes(current.hash), to_bytes(expected_hash));
}

}  // namespace license::fingerprint
