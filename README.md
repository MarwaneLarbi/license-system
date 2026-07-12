# Offline License Key Management System

A C++20, CMake-based, **fully offline** license key management system.  
**Zero source-code changes required** — all key material, rotation, and issuance is driven entirely through CLI commands and JSON files.

| Component | Description |
|---|---|
| `license-server` | Vendor tool (air-gapped). Generates keystore + `server_pubkeys.json`, issues signed tokens. |
| `license-client` | Customer / installer tool. Generates request blobs, activates, verifies, deactivates. |
| `liblicenseclient` | Static library embedded in the SaaS product. Loads keys from `server_pubkeys.json` at runtime. |

No network connection is ever required or used. No source-code editing is needed for key deployment or rotation.

---

## How It Works — At a Glance

```
VENDOR MACHINE (air-gapped)
  license-server init-keys --keystore vendor.json --pub-out server_pubkeys.json
       └─ writes encrypted keystore (private keys, NEVER leaves vendor machine)
       └─ writes server_pubkeys.json (public keys only — distribute to customers)

                ┌─────────────────────────────────────┐
                │  Distribute: server_pubkeys.json    │  ← ship alongside client binary
                └─────────────────────────────────────┘

CUSTOMER MACHINE
  license-client --config server_pubkeys.json generate-request myapp-pro "Alice"
       └─ outputs an encrypted base64 blob  ────────────────── ✉  email to vendor

VENDOR MACHINE
  license-server generate-license --keystore vendor.json --blob <blob> --product myapp-pro
       └─ decrypts blob, signs license  ──────────────────────── ✉  email token back

CUSTOMER MACHINE
  license-client --config server_pubkeys.json activate <token>
  license-client --config server_pubkeys.json verify   myapp-pro
       └─ seals token into TPM; verifies on every startup
```

**Key insight:** `server_pubkeys.json` is the only file that ever leaves the vendor machine. It contains only public keys and is safe to distribute openly. The keystore (containing private keys) never leaves the vendor's air-gapped machine.

---

## Project Structure

```
license-system/
├── CMakeLists.txt              Root — finds OpenSSL, Argon2, tpm2-tss; FetchContent json/Catch2
├── README.md
│
├── common/                     Shared static library (client + server)
│   ├── include/
│   │   ├── crypto.h            Crypto API: X25519, Ed25519, AES-256-GCM, HKDF, hybrid encrypt
│   │   ├── fingerprint.h       Hardware fingerprint API
│   │   ├── tpm_provider.h      ITpmProvider interface + create_provider() factory
│   │   ├── license.h           LicenseRequest, LicenseRecord, sign/verify, UUID, anti-replay
│   │   └── keystore.h          Argon2id-encrypted server keystore API
│   └── src/
│       ├── crypto.cpp          OpenSSL 3.x EVP implementation (no deprecated APIs)
│       ├── fingerprint.cpp     Linux /sys + Windows SMBIOS/SetupAPI/CPUID
│       ├── tpm_software.cpp    Software fallback: DPAPI (Windows) / AES-GCM+keyfile (Linux)
│       ├── tpm_linux.cpp       tpm2-tss ESAPI: EK, PCR 0+7 seal/unseal policy
│       ├── tpm_windows.cpp     Windows TBS API backend
│       ├── license.cpp         JSON serialisation, sign_license, verify_license, generate_uuid
│       └── keystore.cpp        Argon2id KDF + AES-256-GCM keystore, OPENSSL_cleanse throughout
│
├── client/
│   ├── include/
│   │   └── license_client.h   Public API — keys loaded at runtime from server_pubkeys.json
│   └── src/
│       ├── license_client.cpp  generate_request / activate / verify_at_startup / deactivate
│       └── main.cpp            CLI: all commands + --config + --json flags
│
├── server/
│   └── src/
│       └── main.cpp            CLI: init-keys / generate-license + --json flags
│
├── tests/
│   ├── test_crypto.cpp         ~40 crypto primitive tests (Catch2)
│   ├── test_fingerprint.cpp    Fingerprint stability + verify tests
│   └── test_license.cpp        Serialisation, token sign/verify, expiry, keystore tests
│
└── scripts/
    └── end_to_end.sh           Full demo — runs the complete vendor↔customer exchange
```

---

## Building

### Prerequisites

| Dependency | Linux | Windows |
|---|---|---|
| CMake ≥ 3.20 | `apt install cmake` | [cmake.org](https://cmake.org) |
| C++20 compiler | `apt install build-essential` | MSVC 2022 or clang-cl |
| OpenSSL 3.x | `apt install libssl-dev` | [openssl.org/source](https://openssl.org/source) |
| Argon2 | `apt install libargon2-dev` | auto via FetchContent |
| tpm2-tss (optional) | `apt install libtss2-dev` | not required |
| nlohmann/json | auto via FetchContent | auto |
| Catch2 v3 (tests) | auto via FetchContent | auto |

### Linux

```bash
sudo apt-get install build-essential cmake libssl-dev libargon2-dev \
                     libtss2-dev pkg-config

cmake -B build -DCMAKE_BUILD_TYPE=Release -DLICENSE_BUILD_TESTS=ON
cmake --build build --parallel

cd build && ctest --output-on-failure
```

### Windows (MSVC)

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64 `
      -DOPENSSL_ROOT_DIR="C:/Program Files/OpenSSL-Win64" `
      -DLICENSE_BUILD_TESTS=ON
cmake --build build --config Release
```

### CMake flags

| Flag | Default | Description |
|---|---|---|
| `LICENSE_ENABLE_TPM` | `ON` | Enable TPM 2.0 hardware backend |
| `LICENSE_BUILD_TESTS` | `ON` | Build Catch2 unit tests |
| `LICENSE_SANITIZERS` | `OFF` | ASan + UBSan in Debug builds |

---

## Complete CLI Reference

### `license-server`

#### `init-keys` — Generate server keypair

```
license-server init-keys
    --keystore  <path>            Encrypted keystore to create (private keys)
    --pub-out   <path>            Write server_pubkeys.json here
                                  [default: server_pubkeys.json]
    [--passphrase <pass>]         Prompted securely if omitted
    [--json]                      JSON output
```

**Output** — `server_pubkeys.json`:
```json
{
  "version": "1",
  "server_x25519_pub":  "<base64, 32 bytes>",
  "server_ed25519_pub": "<base64, 32 bytes>"
}
```

Distribute this file to customers alongside the `license-client` binary.  
**Never** share the keystore file or passphrase.

---

#### `generate-license` — Issue a signed license

```
license-server generate-license
    --keystore         <path>     Keystore from init-keys
    --blob             <base64>   Encrypted request blob from customer
    --product          <id>       Product identifier
    [--features        f1,f2,…]  Comma-separated feature list
    [--days            <N>]       Validity period in days [default: 365]
                                  Use 0 for no expiry
    [--max-activations <N>]       [default: 1]
    [--passphrase      <pass>]    Prompted securely if omitted
    [--json]                      JSON output (token in "token" field)
```

**Plain output** (default): token on `stdout`, human summary on `stderr`.  
**JSON output** (`--json`): full record + token in `stdout` as JSON.

---

### `license-client`

```
license-client [--config <server_pubkeys.json>] [--json] <command> [args…]
```

Global flags must appear **before** the subcommand.

| Flag | Default | Description |
|---|---|---|
| `--config <path>` | `./server_pubkeys.json` | Path to server public-key config |
| `--json` | off | Output results as JSON |

---

#### `generate-request` — Create encrypted request blob

```
license-client --config server_pubkeys.json generate-request <product_id> [customer_hint]
```

Outputs the encrypted blob to `stdout` (plain) or `{ "blob": "…" }` (JSON).  
Email/paste the blob to the vendor.

---

#### `activate` — Activate a license token

```
license-client --config server_pubkeys.json activate <token>
```

Verifies Ed25519 signature, hardware fingerprint, and expiry.  
Seals the token into TPM-protected local storage.

---

#### `verify` — Verify license at startup

```
license-client --config server_pubkeys.json verify <product_id>
```

Unseals from TPM, re-verifies signature, fingerprint, and expiry.  
Exit code 0 = valid, non-zero = invalid.

---

#### `deactivate` — Remove local license

```
license-client deactivate <product_id>
```

Overwrites the sealed blob with random bytes, then deletes it.

---

#### `fingerprint` — Diagnostic hardware fingerprint

```
license-client [--json] fingerprint
```

Prints the current machine's fingerprint hash and component list.

---

## Embedding `liblicenseclient` in Your Product

```cpp
#include "license_client.h"

int main() {
    // Load keys from the JSON file — no hardcoded constants.
    auto keys = license::client::load_server_keys("server_pubkeys.json");

    auto result = license::client::verify_at_startup("myapp-pro", keys);
    if (!result.valid) {
        std::cerr << "License check failed: " << result.error << "\n";
        return 1;
    }
    // result.license_id, result.features, result.expires_at available here.
}
```

`server_pubkeys.json` can live next to the executable, in a config directory, or at a path you choose. Pass the path to `load_server_keys()`.

---

## Key Rotation (no code changes required)

If the server signing key is compromised or you want to rotate on schedule:

```bash
# 1. Generate new keystore + new server_pubkeys.json
license-server init-keys \
    --keystore  new_keystore.json \
    --pub-out   new_server_pubkeys.json

# 2. Distribute new_server_pubkeys.json to customers
#    (replace the old file; client binary does NOT need to be rebuilt)

# 3. Re-issue licenses for all customers using the new keystore
license-server generate-license --keystore new_keystore.json --blob <blob> …

# 4. Old tokens (signed with the old key) are automatically rejected
#    by any client using the new server_pubkeys.json
```

No rebuild of `license-client` or `liblicenseclient` is required.  
Old licenses become invalid as soon as customers replace `server_pubkeys.json`.

---

## Security Properties

### Hardware binding

| Assurance | Bound to |
|---|---|
| `hardware` | TPM Endorsement Key + SMBIOS UUID + CPU ID + disk serial. Sealed under PCR 0+7 policy — inaccessible if copied to another machine or after Secure Boot/firmware changes. |
| `software` | SMBIOS UUID + CPU ID + disk serial. Protected by DPAPI (Windows) or AES-GCM + machine secret file (Linux). |

### Cryptography

| Purpose | Algorithm |
|---|---|
| Request encryption | Hybrid: ephemeral X25519 + HKDF-SHA256 + AES-256-GCM |
| License signing | Ed25519 (deterministic RFC 8032) |
| Fingerprint hashing | SHA-256 with length-prefixed canonical input |
| Keystore KDF | Argon2id (t=3, m=128 MiB, p=4 default) |
| Keystore encryption | AES-256-GCM |
| Security-critical comparisons | OpenSSL `CRYPTO_memcmp` (constant-time) |

- OpenSSL 3.x EVP API only — zero deprecated low-level calls.
- All nonces randomly generated per message.
- `OPENSSL_cleanse` used on all private key material before free.
- No key material written to disk in plaintext or logged.

### Anti-replay

Request blobs include a timestamp and a 16-byte random nonce.  
The server rejects blobs with timestamps older than 24 hours.

---

## Running Tests

```bash
cd build
ctest --output-on-failure -V

# Or directly for verbose output:
./tests/license_tests --reporter=spec
```

---

## Running the Demo Script

```bash
chmod +x scripts/end_to_end.sh
LICENSE_CLIENT=./build/client/license-client \
LICENSE_SERVER=./build/server/license-server \
./scripts/end_to_end.sh
```

The demo uses a software TPM fallback and ephemeral files — no hardware TPM needed.

---

## License

MIT. Cryptographic design follows TCG TPM 2.0 Library Specification, IETF RFC 7748 (X25519), RFC 8032 (Ed25519), and RFC 5869 (HKDF).
#   l i c e n s e - s y s t e m  
 