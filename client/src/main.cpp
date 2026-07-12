/**
 * main.cpp — license-client CLI
 *
 * All operations are driven entirely from the command line.
 * Server public keys are loaded from a JSON config file at runtime —
 * no source code changes ever needed.
 *
 * Usage:
 *   license-client --config <server_pubkeys.json> generate-request <product_id> [customer_hint]
 *   license-client --config <server_pubkeys.json> activate <token>
 *   license-client --config <server_pubkeys.json> verify <product_id>
 *   license-client deactivate <product_id>
 *   license-client fingerprint
 *
 * Global flags (before the subcommand):
 *   --config <path>   Path to server_pubkeys.json  [default: ./server_pubkeys.json]
 *   --json            Output results as JSON (exit code still signals success/failure)
 *   --help / -h       Print usage
 *
 * The server_pubkeys.json is produced by:
 *   license-server init-keys --keystore <path> --pub-out server_pubkeys.json
 */

#include "license_client.h"
#include "fingerprint.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

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
// Usage
// ──────────────────────────────────────────────

static void print_usage(const char* argv0) {
    std::cerr
        << "Usage:\n"
        << "  " << argv0 << " [--config <server_pubkeys.json>] [--json] generate-request <product_id> [customer_hint]\n"
        << "  " << argv0 << " [--config <server_pubkeys.json>] [--json] activate <token>\n"
        << "  " << argv0 << " [--config <server_pubkeys.json>] [--json] verify <product_id>\n"
        << "  " << argv0 << " [--json] deactivate <product_id>\n"
        << "  " << argv0 << " [--json] fingerprint\n"
        << "\n"
        << "Global flags:\n"
        << "  --config <path>   Path to server_pubkeys.json  [default: ./server_pubkeys.json]\n"
        << "  --json            Output results as machine-readable JSON\n"
        << "\n"
        << "Generate server_pubkeys.json with:\n"
        << "  license-server init-keys --keystore <path> --pub-out server_pubkeys.json\n";
}

// ──────────────────────────────────────────────
// JSON error helper
// ──────────────────────────────────────────────

static int json_error(const std::string& error, bool as_json) {
    if (as_json)
        std::cout << json{{"success", false}, {"error", error}}.dump(2) << "\n";
    else
        std::cerr << "Error: " << error << "\n";
    return EXIT_FAILURE;
}

// ──────────────────────────────────────────────
// Commands
// ──────────────────────────────────────────────

static int cmd_generate_request(const std::vector<std::string>& args,
                                 const license::client::ServerKeys& keys,
                                 bool as_json)
{
    // Find subcommand position, then positional args follow.
    auto it = std::find(args.begin(), args.end(), "generate-request");
    if (it == args.end() || std::next(it) == args.end())
        return json_error("generate-request requires <product_id>", as_json);

    std::string product_id    = *std::next(it);
    std::string customer_hint = (std::next(it, 2) != args.end()) ? *std::next(it, 2) : "";

    auto r = license::client::generate_request(product_id, customer_hint, keys);

    if (as_json) {
        json out;
        out["success"] = r.success;
        if (r.success) {
            out["blob"]                  = r.blob_b64;
            out["fingerprint_hash"]       = r.fingerprint_hash;
            out["fingerprint_assurance"]  = r.fingerprint_assurance;
        } else {
            out["error"] = r.error;
        }
        std::cout << out.dump(2) << "\n";
    } else {
        if (!r.success) {
            std::cerr << "Error: " << r.error << "\n";
            return EXIT_FAILURE;
        }
        // Machine-readable blob on stdout, human info on stderr.
        std::cout << r.blob_b64 << "\n";
        std::cerr << "[OK] Request blob generated.\n"
                  << "     fingerprint:  " << r.fingerprint_hash.substr(0, 16) << "...\n"
                  << "     assurance:    " << r.fingerprint_assurance << "\n"
                  << "     Send the blob above to your vendor.\n";
    }
    return r.success ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int cmd_activate(const std::vector<std::string>& args,
                         const license::client::ServerKeys& keys,
                         bool as_json)
{
    auto it = std::find(args.begin(), args.end(), "activate");
    if (it == args.end() || std::next(it) == args.end())
        return json_error("activate requires <token>", as_json);

    std::string token = *std::next(it);
    auto r = license::client::activate(token, keys);

    if (as_json) {
        json out;
        out["success"] = r.success;
        if (r.success) {
            out["license_id"] = r.license_id;
            out["product_id"] = r.product_id;
        } else {
            out["error"] = r.error;
        }
        std::cout << out.dump(2) << "\n";
    } else {
        if (!r.success) {
            std::cerr << "Error: " << r.error << "\n";
            return EXIT_FAILURE;
        }
        std::cout << "[OK] License activated.\n"
                  << "     license_id: " << r.license_id << "\n"
                  << "     product_id: " << r.product_id << "\n";
    }
    return r.success ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int cmd_verify(const std::vector<std::string>& args,
                       const license::client::ServerKeys& keys,
                       bool as_json)
{
    auto it = std::find(args.begin(), args.end(), "verify");
    if (it == args.end() || std::next(it) == args.end())
        return json_error("verify requires <product_id>", as_json);

    std::string product_id = *std::next(it);
    auto r = license::client::verify_at_startup(product_id, keys);

    if (as_json) {
        json out;
        out["valid"] = r.valid;
        if (r.valid) {
            out["license_id"]      = r.license_id;
            out["product_id"]      = r.product_id;
            out["assurance_level"] = r.assurance_level;
            out["issued_at"]       = r.issued_at;
            out["expires_at"]      = r.expires_at;
            out["features"]        = r.features;
        } else {
            out["error"] = r.error;
        }
        std::cout << out.dump(2) << "\n";
    } else {
        if (!r.valid) {
            std::cerr << "INVALID: " << r.error << "\n";
            return EXIT_FAILURE;
        }
        std::cout << "VALID\n"
                  << "  license_id:  " << r.license_id        << "\n"
                  << "  product_id:  " << r.product_id         << "\n"
                  << "  assurance:   " << r.assurance_level     << "\n"
                  << "  issued_at:   " << r.issued_at           << "\n"
                  << "  expires_at:  " << (r.expires_at == 0 ? "never" : std::to_string(r.expires_at)) << "\n"
                  << "  features:    ";
        for (const auto& f : r.features) std::cout << f << " ";
        std::cout << "\n";
    }
    return r.valid ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int cmd_deactivate(const std::vector<std::string>& args, bool as_json) {
    auto it = std::find(args.begin(), args.end(), "deactivate");
    if (it == args.end() || std::next(it) == args.end())
        return json_error("deactivate requires <product_id>", as_json);

    std::string product_id = *std::next(it);
    bool ok = license::client::deactivate(product_id);

    if (as_json) {
        std::cout << json{{"success", ok},
                          {"product_id", product_id}}.dump(2) << "\n";
    } else {
        if (ok) std::cout << "[OK] License deactivated for: " << product_id << "\n";
        else    std::cerr << "Error: deactivation failed.\n";
    }
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int cmd_fingerprint(bool as_json) {
    auto fp = license::fingerprint::compute(/*use_tpm=*/true);

    if (as_json) {
        json out;
        out["hash"]            = fp.hash;
        out["tpm_bound"]       = fp.tpm_bound;
        out["assurance_level"] = fp.assurance_level;
        out["components"]      = fp.components;
        std::cout << out.dump(2) << "\n";
    } else {
        std::cout << "hash:       " << fp.hash                          << "\n"
                  << "tpm_bound:  " << (fp.tpm_bound ? "yes" : "no")   << "\n"
                  << "assurance:  " << fp.assurance_level               << "\n"
                  << "components:\n";
        for (const auto& c : fp.components)
            std::cout << "  " << c << "\n";
    }
    return EXIT_SUCCESS;
}

// ──────────────────────────────────────────────
// main
// ──────────────────────────────────────────────

int main(int argc, char* argv[]) {
    std::vector<std::string> args(argv + 1, argv + argc);

    if (args.empty() || has_flag(args, "--help") || has_flag(args, "-h")) {
        print_usage(argv[0]);
        return args.empty() ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    bool        as_json     = has_flag(args, "--json");
    std::string config_path = get_arg(args, "--config", "server_pubkeys.json");

    // Find the subcommand (first arg that does not start with '-').
    std::string cmd;
    for (const auto& a : args) {
        if (a[0] != '-') { cmd = a; break; }
    }

    // Commands that do not need server keys.
    if (cmd == "fingerprint") return cmd_fingerprint(as_json);
    if (cmd == "deactivate")  return cmd_deactivate(args, as_json);

    if (cmd.empty()) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Commands that need server keys — load them now.
    license::client::ServerKeys keys;
    try {
        keys = license::client::load_server_keys(config_path);
    } catch (const std::exception& e) {
        return json_error(e.what(), as_json);
    }

    if (cmd == "generate-request") return cmd_generate_request(args, keys, as_json);
    if (cmd == "activate")         return cmd_activate(args, keys, as_json);
    if (cmd == "verify")           return cmd_verify(args, keys, as_json);

    std::cerr << "Unknown command: " << cmd << "\n";
    print_usage(argv[0]);
    return EXIT_FAILURE;
}
