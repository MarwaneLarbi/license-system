cmake_minimum_required(VERSION 3.20)
project(LicenseSystem
        VERSION 1.0.0
        DESCRIPTION "Offline license key management system"
        LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ──────────────────────────────────────────────
# Build options
# ──────────────────────────────────────────────
option(LICENSE_ENABLE_TPM   "Enable TPM 2.0 hardware support"  ON)
option(LICENSE_BUILD_TESTS  "Build unit tests"                  ON)
option(LICENSE_SANITIZERS   "Enable ASan/UBSan in Debug"        OFF)

# ──────────────────────────────────────────────
# Compiler hardening flags
# ──────────────────────────────────────────────
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Werror=format-security
        -fstack-protector-strong
        -fPIE
    )
    # _FORTIFY_SOURCE requires optimisation > 0; safe in Release/RelWithDebInfo.
    add_compile_definitions($<$<NOT:$<CONFIG:Debug>>:_FORTIFY_SOURCE=2>)

    # Hardened linker flags — Linux only (macOS ld does not support -z).
    if(NOT APPLE)
        add_link_options(-Wl,-z,relro -Wl,-z,now)
    endif()
    add_link_options(-pie)

    if(LICENSE_SANITIZERS)
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
    endif()

elseif(MSVC)
    add_compile_options(/W4 /WX /GS /guard:cf /DYNAMICBASE /NXCOMPAT)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS=0)
endif()

# ──────────────────────────────────────────────
# Dependencies via FetchContent
# ──────────────────────────────────────────────
include(FetchContent)

FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(nlohmann_json)

if(LICENSE_BUILD_TESTS)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG        v3.5.2
    )
    FetchContent_MakeAvailable(Catch2)
    list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
    include(CTest)
    include(Catch)
endif()

# ──────────────────────────────────────────────
# OpenSSL (required)
# ──────────────────────────────────────────────
find_package(OpenSSL 3.0 REQUIRED)

# ──────────────────────────────────────────────
# Argon2 (required for keystore KDF)
# Falls back to FetchContent if not found system-wide.
# ──────────────────────────────────────────────
find_path(ARGON2_INCLUDE_DIR argon2.h)
find_library(ARGON2_LIBRARY NAMES argon2 libargon2)
if(NOT ARGON2_INCLUDE_DIR OR NOT ARGON2_LIBRARY)
    message(STATUS "System argon2 not found — building from source via FetchContent")
    FetchContent_Declare(
        phc-winner-argon2
        GIT_REPOSITORY https://github.com/P-H-C/phc-winner-argon2.git
        GIT_TAG        20190702
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(phc-winner-argon2)
    set(ARGON2_INCLUDE_DIR ${phc-winner-argon2_SOURCE_DIR}/include)
    set(ARGON2_LIBRARY     argon2)
else()
    message(STATUS "Found system argon2: ${ARGON2_LIBRARY}")
endif()

# ──────────────────────────────────────────────
# TPM2-TSS (optional, Linux only)
# ──────────────────────────────────────────────
if(LICENSE_ENABLE_TPM AND UNIX AND NOT APPLE)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(TSS2_ESYS    tss2-esys)
        pkg_check_modules(TSS2_MU      tss2-mu)
        pkg_check_modules(TSS2_SYS     tss2-sys)
        pkg_check_modules(TSS2_TCTILDR tss2-tctildr)
    endif()
    if(TSS2_ESYS_FOUND)
        message(STATUS "TPM2-TSS (ESAPI) found — TPM hardware backend enabled")
        add_compile_definitions(HAVE_TPM2_TSS=1)
    else()
        message(WARNING "TPM2-TSS not found — software-only TPM provider will be used")
    endif()
endif()

if(WIN32 AND LICENSE_ENABLE_TPM)
    add_compile_definitions(HAVE_TBS=1)
    message(STATUS "Windows TBS API — TPM hardware backend enabled")
endif()

# ──────────────────────────────────────────────
# Sub-directories
# ──────────────────────────────────────────────
add_subdirectory(common)
add_subdirectory(client)
add_subdirectory(server)

if(LICENSE_BUILD_TESTS)
    add_subdirectory(tests)
endif()
