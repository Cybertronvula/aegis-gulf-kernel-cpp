/**
 * Aegis Gulf Compliance Kernel — AES-256-GCM Implementation
 * ===========================================================
 * engine.cpp  |  v0.1.0  |  C++20
 *
 * Production implementation of the AegisKernel interface.
 * Uses OpenSSL 3.x EVP API for:
 *   - AES-256-GCM authenticated encryption (POPIA Section 19)
 *   - SHA-256 HMAC audit chain (tamper-evidence)
 *
 * Hardware acceleration:
 *   Intel AES-NI and ARMv8 Crypto Extensions are used automatically
 *   when available — OpenSSL detects and uses hardware paths at runtime
 *   via CPUID/HWCAP flags. No manual configuration required.
 *
 * Compile:
 *   g++ -std=c++20 -O3 -march=native engine.cpp -o engine.o -c \
 *       -lssl -lcrypto
 *
 * Author: Nvula Bontes — Lead Architect, Aegis Gulf
 *         Kimberley, Northern Cape, South Africa
 */

#include "engine.hpp"

// OpenSSL 3.x EVP API
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstring>
#include <format>
#include <mutex>
#include <stdexcept>
#include <string>

namespace aegis {

// ── OpenSSL RAII helpers ──────────────────────────────────────────────────────

/// RAII wrapper for EVP_CIPHER_CTX
struct EvpCtxGuard {
    EVP_CIPHER_CTX* ctx;
    explicit EvpCtxGuard()  : ctx(EVP_CIPHER_CTX_new()) {
        if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }
    ~EvpCtxGuard() { EVP_CIPHER_CTX_free(ctx); }
    EvpCtxGuard(const EvpCtxGuard&) = delete;
    EvpCtxGuard& operator=(const EvpCtxGuard&) = delete;
};

/// RAII wrapper for EVP_MAC_CTX
struct EvpMacCtxGuard {
    EVP_MAC_CTX* ctx;
    explicit EvpMacCtxGuard(EVP_MAC* mac) : ctx(EVP_MAC_CTX_new(mac)) {
        if (!ctx) throw std::runtime_error("EVP_MAC_CTX_new failed");
    }
    ~EvpMacCtxGuard() { EVP_MAC_CTX_free(ctx); }
    EvpMacCtxGuard(const EvpMacCtxGuard&) = delete;
    EvpMacCtxGuard& operator=(const EvpMacCtxGuard&) = delete;
};

/// Generate cryptographically secure random bytes
static void secure_random(std::span<uint8_t> out) {
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed — entropy source unavailable");
    }
}

// ── AES-256-GCM encrypt ───────────────────────────────────────────────────────

/**
 * Encrypt plaintext using AES-256-GCM.
 *
 * GCM provides both confidentiality AND authentication in a single pass.
 * The auth_tag authenticates the ciphertext — any modification is detected
 * during decryption without the need for a separate HMAC.
 *
 * We use HMAC separately on top for the audit CHAIN (linking entries),
 * which is a different security property from per-entry authentication.
 *
 * @param key        32-byte AES-256 key
 * @param nonce      12-byte GCM nonce (MUST be unique per key — we use RAND_bytes)
 * @param plaintext  Data to encrypt
 * @param ciphertext Output ciphertext (same length as plaintext)
 * @param auth_tag   Output 16-byte GCM authentication tag
 */
static Result<void> aes256gcm_encrypt(
    const KeyBytes&            key,
    const NonceBytes&          nonce,
    std::span<const uint8_t>   plaintext,
    std::vector<uint8_t>&      ciphertext,
    TagBytes&                  auth_tag
) noexcept {
    try {
        EvpCtxGuard ctx;

        // Initialise AES-256-GCM context
        // OpenSSL automatically uses AES-NI / ARMv8 hardware if available
        if (EVP_EncryptInit_ex(ctx.ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
            return Result<void>(KernelError::EncryptionFailed);

        // Set IV (nonce) length explicitly — GCM standard is 12 bytes
        if (EVP_CIPHER_CTX_ctrl(ctx.ctx, EVP_CTRL_GCM_SET_IVLEN,
                                 static_cast<int>(NONCE_BYTES), nullptr) != 1)
            return Result<void>(KernelError::EncryptionFailed);

        // Provide key and IV
        if (EVP_EncryptInit_ex(ctx.ctx, nullptr, nullptr,
                                key.data(), nonce.data()) != 1)
            return Result<void>(KernelError::EncryptionFailed);

        // Encrypt
        ciphertext.resize(plaintext.size());
        int outlen = 0;
        if (EVP_EncryptUpdate(ctx.ctx,
                               ciphertext.data(), &outlen,
                               plaintext.data(),
                               static_cast<int>(plaintext.size())) != 1)
            return Result<void>(KernelError::EncryptionFailed);

        // Finalise (GCM produces no additional output here but must be called)
        int final_len = 0;
        if (EVP_EncryptFinal_ex(ctx.ctx,
                                 ciphertext.data() + outlen,
                                 &final_len) != 1)
            return Result<void>(KernelError::EncryptionFailed);

        // Extract GCM authentication tag
        if (EVP_CIPHER_CTX_ctrl(ctx.ctx, EVP_CTRL_GCM_GET_TAG,
                                 static_cast<int>(TAG_BYTES),
                                 auth_tag.data()) != 1)
            return Result<void>(KernelError::EncryptionFailed);

        return Result<void>{};
    } catch (...) {
        return Result<void>(KernelError::EncryptionFailed);
    }
}

// ── AES-256-GCM decrypt ───────────────────────────────────────────────────────

static Result<std::vector<uint8_t>> aes256gcm_decrypt(
    const KeyBytes&            key,
    const NonceBytes&          nonce,
    std::span<const uint8_t>   ciphertext,
    const TagBytes&            auth_tag
) noexcept {
    try {
        EvpCtxGuard ctx;

        if (EVP_DecryptInit_ex(ctx.ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
            return Result<void>(KernelError::DecryptionFailed);

        if (EVP_CIPHER_CTX_ctrl(ctx.ctx, EVP_CTRL_GCM_SET_IVLEN,
                                 static_cast<int>(NONCE_BYTES), nullptr) != 1)
            return Result<void>(KernelError::DecryptionFailed);

        if (EVP_DecryptInit_ex(ctx.ctx, nullptr, nullptr,
                                key.data(), nonce.data()) != 1)
            return Result<void>(KernelError::DecryptionFailed);

        std::vector<uint8_t> plaintext(ciphertext.size());
        int outlen = 0;

        if (EVP_DecryptUpdate(ctx.ctx,
                               plaintext.data(), &outlen,
                               ciphertext.data(),
                               static_cast<int>(ciphertext.size())) != 1)
            return Result<void>(KernelError::DecryptionFailed);

        // Set expected tag — EVP_DecryptFinal_ex will verify it
        if (EVP_CIPHER_CTX_ctrl(ctx.ctx, EVP_CTRL_GCM_SET_TAG,
                                 static_cast<int>(TAG_BYTES),
                                 const_cast<uint8_t*>(auth_tag.data())) != 1)
            return Result<void>(KernelError::DecryptionFailed);

        int final_len = 0;
        // Returns <= 0 if tag verification fails — ciphertext was tampered
        if (EVP_DecryptFinal_ex(ctx.ctx,
                                 plaintext.data() + outlen,
                                 &final_len) <= 0)
            return Result<void>(KernelError::DecryptionFailed);

        plaintext.resize(outlen + final_len);
        return plaintext;
    } catch (...) {
        return Result<void>(KernelError::DecryptionFailed);
    }
}

// ── SHA-256 HMAC chain link ───────────────────────────────────────────────────

/**
 * Compute HMAC-SHA-256 over (prev_hmac || ciphertext).
 *
 * The chain input is the concatenation of the previous entry's HMAC
 * and the current entry's ciphertext. This creates an unforgeable
 * chain — modifying any entry changes its HMAC, which invalidates
 * every subsequent entry's HMAC.
 *
 * We use HMAC (not just SHA-256) so that the chain is bound to the
 * kernel's HMAC key — an attacker who modifies ciphertext cannot
 * recompute a valid HMAC without the key.
 */
static Result<HmacBytes> compute_chain_hmac(
    const KeyBytes&          hmac_key,
    const HmacBytes&         prev_hmac,
    std::span<const uint8_t> ciphertext
) noexcept {
    try {
        HmacBytes result{};
        unsigned int result_len = static_cast<unsigned int>(HMAC_BYTES);

        // Build input: prev_hmac || ciphertext
        std::vector<uint8_t> input;
        input.reserve(HMAC_BYTES + ciphertext.size());
        input.insert(input.end(), prev_hmac.begin(), prev_hmac.end());
        input.insert(input.end(), ciphertext.begin(), ciphertext.end());

        // HMAC-SHA-256 using legacy HMAC API (compatible with OpenSSL 1.x and 3.x)
        const uint8_t* out = HMAC(
            EVP_sha256(),
            hmac_key.data(), static_cast<int>(HMAC_BYTES),
            input.data(),    static_cast<int>(input.size()),
            result.data(),   &result_len
        );

        if (!out || result_len != HMAC_BYTES)
            return Result<void>(KernelError::HmacFailed);

        return result;
    } catch (...) {
        return Result<void>(KernelError::HmacFailed);
    }
}

// ── Constant-time comparison ──────────────────────────────────────────────────

/// Timing-attack-resistant HMAC comparison using CRYPTO_memcmp
static bool hmac_equal(const HmacBytes& a, const HmacBytes& b) noexcept {
    return CRYPTO_memcmp(a.data(), b.data(), HMAC_BYTES) == 0;
}

// ── Timestamp ────────────────────────────────────────────────────────────────

static uint64_t now_ns() noexcept {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<nanoseconds>(
            system_clock::now().time_since_epoch()
        ).count()
    );
}

// ── Production kernel implementation ─────────────────────────────────────────

class AesChainingKernel final : public AegisKernel {
public:
    explicit AesChainingKernel(
        std::optional<KeyBytes> enc_key  = std::nullopt,
        std::optional<KeyBytes> hmac_key = std::nullopt
    ) {
        // Generate random keys if not provided
        if (enc_key)  { enc_key_  = *enc_key; }
        else          { secure_random(enc_key_); }

        if (hmac_key) { hmac_key_ = *hmac_key; }
        else          { secure_random(hmac_key_); }

        start_time_ = std::chrono::steady_clock::now();
    }

    // ── archive ──────────────────────────────────────────────────────────────
    Result<VaultEntry> archive(
        std::string_view event_type,
        std::string_view payload_json,
        std::string_view metadata_json
    ) override {
        // Build plaintext: JSON envelope with event type + payload + timestamp
        const auto plaintext_str = std::format(
            R"({{"event_type":"{}","payload":{},"timestamp_ns":{}}})",
            event_type, payload_json, now_ns()
        );
        const auto* plain_data = reinterpret_cast<const uint8_t*>(plaintext_str.data());
        std::span<const uint8_t> plaintext{plain_data, plaintext_str.size()};

        // Generate fresh random nonce — CRITICAL: never reuse with same key
        NonceBytes nonce{};
        secure_random(nonce);

        // AES-256-GCM encrypt
        std::vector<uint8_t> ciphertext;
        TagBytes auth_tag{};
        auto enc_result = aes256gcm_encrypt(enc_key_, nonce, plaintext,
                                             ciphertext, auth_tag);
        if (!enc_result) return std::unexpected(enc_result.error());

        // SHA-256 HMAC chain link
        std::unique_lock lock(vault_mutex_);

        auto hmac_result = compute_chain_hmac(
            hmac_key_, last_hmac_,
            std::span<const uint8_t>{ciphertext}
        );
        if (!hmac_result) return std::unexpected(hmac_result.error());

        // Build entry
        VaultEntry entry;
        entry.entry_id      = ++entry_counter_;
        entry.timestamp_ns  = now_ns();
        entry.ciphertext    = std::move(ciphertext);
        entry.nonce         = nonce;
        entry.auth_tag      = auth_tag;
        entry.chain_hmac    = *hmac_result;
        entry.prev_hmac     = last_hmac_;
        entry.metadata_json = std::string(metadata_json);

        last_hmac_ = *hmac_result;
        vault_.push_back(entry);

        // Update stats
        total_bytes_archived_ += plaintext_str.size();
        ++encrypt_ops_;
        ++hmac_ops_;

        return entry;
    }

    // ── verify_chain ─────────────────────────────────────────────────────────
    VerificationResult verify_chain() const override {
        const auto t_start = std::chrono::steady_clock::now();

        std::shared_lock lock(verify_mutex_);
        const auto entries = [&]() {
            std::unique_lock l(vault_mutex_);
            return vault_;
        }();

        if (entries.empty()) {
            return {
                .valid           = true,
                .entries_checked = 0,
                .broken_at_entry_id = std::nullopt,
                .elapsed_ms      = 0.0,
                .message         = "Vault is empty — chain is valid."
            };
        }

        HmacBytes running_hmac = CHAIN_GENESIS;

        for (const auto& entry : entries) {
            auto expected = compute_chain_hmac(
                hmac_key_, running_hmac,
                std::span<const uint8_t>{entry.ciphertext}
            );

            // Constant-time comparison — prevents timing attacks
            if (!expected || !hmac_equal(*expected, entry.chain_hmac)) {
                const auto elapsed = std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - t_start
                ).count();
                return {
                    .valid               = false,
                    .entries_checked     = entry.entry_id,
                    .broken_at_entry_id  = entry.entry_id,
                    .elapsed_ms          = elapsed,
                    .message             = std::format(
                        "CHAIN BROKEN at entry {}. Tampering detected.",
                        entry.entry_id)
                };
            }
            running_hmac = *expected;
        }

        const auto elapsed = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t_start
        ).count();

        return {
            .valid               = true,
            .entries_checked     = static_cast<uint64_t>(entries.size()),
            .broken_at_entry_id  = std::nullopt,
            .elapsed_ms          = elapsed,
            .message             = std::format(
                "Chain verified. All {} entries intact. No tampering detected.",
                entries.size())
        };
    }

    // ── decrypt ──────────────────────────────────────────────────────────────
    Result<std::string> decrypt(const VaultEntry& entry) const override {
        auto result = aes256gcm_decrypt(
            enc_key_, entry.nonce,
            std::span<const uint8_t>{entry.ciphertext},
            entry.auth_tag
        );
        if (!result) return std::unexpected(result.error());
        return std::string(
            reinterpret_cast<const char*>(result->data()),
            result->size()
        );
    }

    // ── stats ─────────────────────────────────────────────────────────────────
    KernelStats stats() const override {
        std::unique_lock lock(vault_mutex_);
        const auto now = std::chrono::steady_clock::now();
        const auto uptime = std::chrono::duration<double>(now - start_time_).count();
        return {
            .total_entries         = static_cast<uint64_t>(vault_.size()),
            .total_bytes_archived  = total_bytes_archived_.load(),
            .uptime_seconds        = uptime,
            .encrypt_ops           = encrypt_ops_.load(),
            .hmac_ops              = hmac_ops_.load(),
        };
    }

    // ── export_json ───────────────────────────────────────────────────────────
    std::string export_json(std::size_t limit) const override {
        std::unique_lock lock(vault_mutex_);
        const std::size_t start = vault_.size() > limit
                                    ? vault_.size() - limit : 0;
        std::string out = "[";
        bool first = true;
        for (std::size_t i = start; i < vault_.size(); ++i) {
            const auto& e = vault_[i];
            if (!first) out += ",";
            first = false;
            // Hex-encode binary fields for JSON output
            auto to_hex = [](std::span<const uint8_t> bytes) {
                static constexpr char hex[] = "0123456789abcdef";
                std::string s; s.reserve(bytes.size() * 2);
                for (auto b : bytes) {
                    s += hex[b >> 4];
                    s += hex[b & 0xF];
                }
                return s;
            };
            out += std::format(
                R"({{"entry_id":{},"timestamp_ns":{},"ciphertext_hex":"{}","nonce_hex":"{}","chain_hmac_hex":"{}","metadata":{}}})",
                e.entry_id,
                e.timestamp_ns,
                to_hex(e.ciphertext).substr(0, 32) + "...",
                to_hex(e.nonce),
                to_hex(e.chain_hmac),
                e.metadata_json
            );
        }
        out += "]";
        return out;
    }

private:
    KeyBytes enc_key_{};
    KeyBytes hmac_key_{};

    mutable std::mutex        vault_mutex_;
    mutable std::shared_mutex verify_mutex_;
    std::vector<VaultEntry>   vault_;
    HmacBytes                 last_hmac_ = CHAIN_GENESIS;
    std::atomic<uint64_t>     entry_counter_{0};
    std::atomic<uint64_t>     total_bytes_archived_{0};
    std::atomic<uint64_t>     encrypt_ops_{0};
    std::atomic<uint64_t>     hmac_ops_{0};
    std::chrono::steady_clock::time_point start_time_;
};

// ── Factory ───────────────────────────────────────────────────────────────────

std::unique_ptr<AegisKernel> make_kernel(
    std::optional<KeyBytes> encryption_key,
    std::optional<KeyBytes> hmac_key
) {
    return std::make_unique<AesChainingKernel>(
        std::move(encryption_key),
        std::move(hmac_key)
    );
}

} // namespace aegis
