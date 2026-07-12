/**
 * main.cpp — license-server CLI (offline / air-gapped vendor tool)
 *
 * All operations are CLI-driven; no source code changes are ever needed.
 *
 * Usage:
 *   license-server init-keys   --keystore <path>
 *                              --pub-out <server_pubkeys.json>
 *                              [--passphrase <pass>]
 *                              [--json]
 *
 *   license-server generate-license
 *                              --keystore <path>
 *                              --blob <base64_blob>
 *                              --product <product_id>
 *                              [--features f1,f2,...]
 *                              [--days <N>]           (default 365; 0 = no expiry)
 *                              [--max-activations <N>](default 1)
 *                              [--passphrase <pass>]
 *                              [--json]
 *
 * --json outputs machine-readable JSON to stdout; human notes go to stderr.
 * Passphrase is prompted securely (no echo) if not supplied via --passphrase.
 * No network calls are ever made.  Designed for air-gapped use.
 */

#include "crypto.h"
#include "fingerprint.h"
#include "keystore.h"
#include "license.h"
#include "tpm_provider.h"

#include <nlohmann/json.hpp>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <termios.h>
#  include <unistd.h>
#endif

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace license;
using json = nlohmann::json;

// ──────────────────────────────────────────────
// Argument helpers
// ──────────────────────────────────────────────

static std::string get_arg(const std::vector<std::string>& args,
                            const std::string& flag,
                            const std::string& default_val = {}) {
    for (std::size_t i = 0; i + 1 < args.size(); ++i)
        if (args[i] == flag) return args[i + 1];
    return default_val;
}

static bool has_flag(const std::vector<std::string>& args, const std::string& flag) {
    return std::find(args.begin(), args.end(), flag) != args.end();
}

// ──────────────────────────────────────────────
// Secure passphrase input (no echo)
// ──────────────────────────────────────────────

static std::string read_passphrase(const std::string& prompt) {
    std::cerr << prompt;
    std::string pass;
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(h, &mode);
    SetConsoleMode(h, mode & ~ENABLE_ECHO_INPUT);
    std::getline(std::cin, pass);
    SetConsoleMode(h, mode);
#else
    struct termios old_term{}, new_term{};
    if (::tcgetattr(STDIN_FILENO, &old_term) == 0) {
        new_term = old_term;
        new_term.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        ::tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
    }
    std::getline(std::cin, pass);
    if (::tcgetattr(STDIN_FILENO, &old_term) == 0)
        ::tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
#endif
    std::cerr << "\n";
    return pass;
}

// ──────────────────────────────────────────────
// Feature list parsing  "feature1,feature2,..."
// ──────────────────────────────────────────────

static std::vector<std::string> parse_features(const std::string& s) {
    std::vector<std::string> out;
    std::istringstream ss(s);
    std::string f;
    while (std::getline(ss, f, ','))
        if (!f.empty()) out.push_back(f);
    return out;
}

// ──────────────────────────────────────────────
// JSON error helper
// ──────────────────────────────────────────────

static int json_error(const std::string& msg, bool as_json) {
    if (as_json)
        std::cout << json{{"success", false}, {"error", msg}}.dump(2) << "\n";
    else
        std::cerr << "Error: " << msg << "\n";
    return EXIT_FAILURE;
}

// ──────────────────────────────────────────────
// init-keys
// ──────────────────────────────────────────────

static int cmd_init_keys(const std::vector<std::string>& args) {
    bool as_json = has_flag(args, "--json");

    std::string keystore_path = get_arg(args, "--keystore");
    std::string pub_out_path  = get_arg(args, "--pub-out", "server_pubkeys.json");

    if (keystore_path.empty())
        return json_error("--keystore <path> is required", as_json);

    // Get passphrase securely.
    std::string passphrase = get_arg(args, "--passphrase");
    if (passphrase.empty()) {
        passphrase = read_passphrase("Enter new keystore passphrase: ");
        auto confirm = read_passphrase("Confirm passphrase: ");
        if (passphrase != confirm)
            return json_error("passphrases do not match", as_json);
    }
    if (passphrase.empty())
        return json_error("empty passphrase is not allowed", as_json);

    // Optional TPM provider.
    auto tpm     = tpm::create_provider();
    auto tpm_ptr = tpm->is_hardware() ? tpm.get() : nullptr;

    keystore::Argon2Params params{}; // defaults: t=3, m=128MiB, p=4
    keystore::PublicKeys pub;
    try {
        pub = keystore::generate_keystore(keystore_path, passphrase, params, tpm_ptr);
    } catch (const std::exception& e) {
        return json_error(std::string("generating keystore: ") + e.what(), as_json);
    }

    // Write server_pubkeys.json for the client.
    json pubkeys_json;
    pubkeys_json["version"]           = "1";
    pubkeys_json["server_x25519_pub"] = pub.x25519_pub_b64;
    pubkeys_json["server_ed25519_pub"]= pub.ed25519_pub_b64;

    try {
        std::ofstream f(pub_out_path);
        if (!f) throw std::runtime_error("Cannot write: " + pub_out_path);
        f << pubkeys_json.dump(2) << "\n";
    } catch (const std::exception& e) {
        return json_error(std::string("writing pub-out file: ") + e.what(), as_json);
    }

    std::cerr << "[OK] Keystore written to:        " << keystore_path << "\n"
              << "[OK] Client public keys written: " << pub_out_path  << "\n";
    if (tpm_ptr)
        std::cerr << "     (keystore master key additionally TPM-sealed on this machine)\n";
    std::cerr << "\n"
              << "Distribute '" << pub_out_path << "' to customers alongside the client binary.\n"
              << "Keep '" << keystore_path << "' and its passphrase SECRET — never share them.\n";

    if (as_json) {
        json out;
        out["success"]            = true;
        out["keystore_path"]      = keystore_path;
        out["pub_out_path"]       = pub_out_path;
        out["tpm_sealed"]         = (tpm_ptr != nullptr);
        out["server_x25519_pub"]  = pub.x25519_pub_b64;
        out["server_ed25519_pub"] = pub.ed25519_pub_b64;
        std::cout << out.dump(2) << "\n";
    } else {
        std::cout << "server_pubkeys.json written to: " << pub_out_path       << "\n"
                  << "server_x25519_pub:              " << pub.x25519_pub_b64  << "\n"
                  << "server_ed25519_pub:             " << pub.ed25519_pub_b64 << "\n";
    }
    return EXIT_SUCCESS;
}

// ──────────────────────────────────────────────
// generate-license
// ──────────────────────────────────────────────

static int cmd_generate_license(const std::vector<std::string>& args) {
    bool as_json = has_flag(args, "--json");

    std::string keystore_path = get_arg(args, "--keystore");
    std::string blob_b64      = get_arg(args, "--blob");
    std::string product_id    = get_arg(args, "--product");
    std::string features_str  = get_arg(args, "--features", "");
    std::string days_str      = get_arg(args, "--days", "365");
    std::string max_act_str   = get_arg(args, "--max-activations", "1");

    if (keystore_path.empty())
        return json_error("--keystore <path> is required", as_json);
    if (blob_b64.empty())
        return json_error("--blob <base64> is required", as_json);
    if (product_id.empty())
        return json_error("--product <product_id> is required", as_json);

    std::string passphrase = get_arg(args, "--passphrase");
    if (passphrase.empty())
        passphrase = read_passphrase("Enter keystore passphrase: ");

    // 1. Load keystore.
    auto tpm     = tpm::create_provider();
    auto tpm_ptr = tpm->is_hardware() ? tpm.get() : nullptr;

    std::unique_ptr<keystore::ServerKeys> keys;
    try {
        keys = keystore::load_keystore(keystore_path, passphrase, tpm_ptr);
    } catch (const std::exception& e) {
        return json_error(std::string("loading keystore: ") + e.what(), as_json);
    }

    // 2. Decode + decrypt the request blob.
    crypto::Bytes blob;
    try {
        blob = crypto::base64_decode(blob_b64);
    } catch (const std::exception& e) {
        return json_error(std::string("invalid base64 blob: ") + e.what(), as_json);
    }

    std::string aad_str = product_id + "|license-client-v" LICENSE_SYSTEM_VERSION;
    crypto::Bytes aad(aad_str.begin(), aad_str.end());

    crypto::Bytes decrypted;
    try {
        decrypted = crypto::hybrid_decrypt(keys->x25519_priv, aad, blob);
    } catch (const std::exception& e) {
        return json_error(std::string("decrypting request blob: ") + e.what(), as_json);
    }

    // 3. Parse request.
    LicenseRequest req;
    try {
        std::string req_json(decrypted.begin(), decrypted.end());
        req = request_from_json(req_json);
    } catch (const std::exception& e) {
        return json_error(std::string("parsing request: ") + e.what(), as_json);
    }

    // 4. Validate.
    if (req.product_id != product_id)
        return json_error("request product_id '" + req.product_id +
                          "' does not match --product '" + product_id + "'", as_json);
    if (!timestamp_is_fresh(req.timestamp))
        return json_error("request timestamp is too old (anti-replay). "
                          "Ask the customer to regenerate the request.", as_json);
    if (req.fingerprint_hash.empty())
        return json_error("request contains no fingerprint hash", as_json);

    // 5. Build license record.
    LicenseRecord rec;
    rec.license_id            = generate_uuid();
    rec.product_id            = product_id;
    rec.fingerprint_hash      = req.fingerprint_hash;
    rec.fingerprint_assurance = req.fingerprint_assurance;
    rec.features              = parse_features(features_str);
    rec.issued_at             = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    int days = std::stoi(days_str);
    rec.expires_at = (days > 0)
        ? rec.issued_at + static_cast<int64_t>(days) * 86400LL
        : 0LL;
    rec.max_activations = static_cast<uint32_t>(std::stoul(max_act_str));

    // 6. Sign.
    std::string token;
    try {
        token = sign_license(rec, keys->ed25519_priv);
    } catch (const std::exception& e) {
        return json_error(std::string("signing license: ") + e.what(), as_json);
    }

    // 7. Output.
    std::cerr << "[OK] License generated:\n"
              << "  license_id:       " << rec.license_id    << "\n"
              << "  product_id:       " << rec.product_id    << "\n"
              << "  customer_hint:    " << req.customer_hint << "\n"
              << "  fingerprint:      " << rec.fingerprint_hash.substr(0, 16) << "...\n"
              << "  assurance:        " << rec.fingerprint_assurance << "\n"
              << "  features:         ";
    for (const auto& f : rec.features) std::cerr << f << " ";
    std::cerr << "\n"
              << "  issued_at:        " << rec.issued_at  << "\n"
              << "  expires_at:       " << (rec.expires_at ? std::to_string(rec.expires_at) : "never") << "\n"
              << "  max_activations:  " << rec.max_activations << "\n";

    if (as_json) {
        json out;
        out["success"]            = true;
        out["token"]              = token;
        out["license_id"]         = rec.license_id;
        out["product_id"]         = rec.product_id;
        out["customer_hint"]      = req.customer_hint;
        out["fingerprint_hash"]   = rec.fingerprint_hash;
        out["assurance"]          = rec.fingerprint_assurance;
        out["features"]           = rec.features;
        out["issued_at"]          = rec.issued_at;
        out["expires_at"]         = rec.expires_at;
        out["max_activations"]    = rec.max_activations;
        std::cout << out.dump(2) << "\n";
    } else {
        // Token-only on stdout for easy pipe/copy.
        std::cout << token << "\n";
        std::cerr << "\nSend the token above to the customer.\n";
    }
    return EXIT_SUCCESS;
}

// ──────────────────────────────────────────────
// main
// ──────────────────────────────────────────────

static void print_usage(const char* argv0) {
    std::cerr
        << "Usage:\n"
        << "  " << argv0 << " init-keys\n"
        << "       --keystore <path>               Encrypted keystore file to create\n"
        << "       --pub-out  <path>               Write server_pubkeys.json here\n"
        << "                                       [default: server_pubkeys.json]\n"
        << "       [--passphrase <pass>]           Prompted if omitted\n"
        << "       [--json]                        JSON output\n"
        << "\n"
        << "  " << argv0 << " generate-license\n"
        << "       --keystore <path>               Keystore file (from init-keys)\n"
        << "       --blob     <base64>             Request blob from customer\n"
        << "       --product  <product_id>         Product identifier\n"
        << "       [--features f1,f2,...]          Feature list [default: none]\n"
        << "       [--days    <N>]                 Validity in days [default: 365]\n"
        << "                                       Use 0 for no expiry\n"
        << "       [--max-activations <N>]         [default: 1]\n"
        << "       [--passphrase <pass>]           Prompted if omitted\n"
        << "       [--json]                        JSON output (token in 'token' field)\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    std::vector<std::string> args(argv + 1, argv + argc);

    if (has_flag(args, "--help") || has_flag(args, "-h")) {
        print_usage(argv[0]);
        return EXIT_SUCCESS;
    }

    const std::string cmd = args[0];
    if (cmd == "init-keys")        return cmd_init_keys(args);
    if (cmd == "generate-license") return cmd_generate_license(args);

    std::cerr << "Unknown command: " << cmd << "\n";
    print_usage(argv[0]);
    return EXIT_FAILURE;
}
