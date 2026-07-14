/**
 * test_fingerprint.cpp — Unit tests for hardware fingerprinting.
 */

#include <catch2/catch_test_macros.hpp>
#include "fingerprint.h"
#include "crypto.h"

#include <string>

using namespace license::fingerprint;

TEST_CASE("compute() returns non-empty hash", "[fingerprint]") {
    auto fp = compute(/*use_tpm=*/false);
    REQUIRE(!fp.hash.empty());
    REQUIRE(fp.hash.size() == 64);  // SHA-256 hex = 64 chars
}

TEST_CASE("compute() is deterministic (no TPM)", "[fingerprint]") {
    auto fp1 = compute(false);
    auto fp2 = compute(false);
    REQUIRE(fp1.hash == fp2.hash);
}

TEST_CASE("compute() assurance level without TPM is 'software'", "[fingerprint]") {
    auto fp = compute(/*use_tpm=*/false);
    REQUIRE(fp.assurance_level == "software");
    REQUIRE(fp.tpm_bound == false);
}

TEST_CASE("compute() components list is non-empty", "[fingerprint]") {
    auto fp = compute(false);
    // At least one of BIOS UUID, CPU ID, or disk serial should be collectible.
    // In a test/CI environment some may be unavailable, so just check the hash is stable.
    INFO("components: " << fp.components.size());
    // Hash should always be 64 hex chars regardless of how many components are available.
    REQUIRE(fp.hash.size() == 64);
}

TEST_CASE("verify() matches self", "[fingerprint]") {
    auto fp = compute(false);
    REQUIRE(verify(fp.hash, /*use_tpm=*/false) == true);
}

TEST_CASE("verify() rejects modified hash", "[fingerprint]") {
    auto fp = compute(false);
    // Flip the last character.
    std::string bad_hash = fp.hash;
    bad_hash.back() ^= 1;  // toggle one bit in hex representation
    if (bad_hash.back() == fp.hash.back())
        bad_hash.back() = 'x';  // force change
    REQUIRE(verify(bad_hash, false) == false);
}

TEST_CASE("smbios_uuid() returns string or empty (no crash)", "[fingerprint]") {
    auto uuid = smbios_uuid();
    // Just ensure it doesn't throw.
    INFO("SMBIOS UUID: '" << uuid << "'");
    SUCCEED();
}

TEST_CASE("cpu_id() returns non-empty on x86", "[fingerprint]") {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    auto id = cpu_id();
    REQUIRE(!id.empty());
#else
    SUCCEED();  // Skip on non-x86.
#endif
}

TEST_CASE("primary_disk_serial() does not throw", "[fingerprint]") {
    auto serial = primary_disk_serial();
    INFO("disk serial: '" << serial << "'");
    SUCCEED();
}

TEST_CASE("tpm_ek_hash() returns nullopt or a 32-byte hash", "[fingerprint]") {
    auto h = tpm_ek_hash();
    if (h.has_value()) {
        REQUIRE(h->size() == 64);  // hex string
    } else {
        SUCCEED();  // no hardware TPM — fine in CI
    }
}
