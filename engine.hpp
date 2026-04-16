/**
 * Aegis Gulf Compliance Kernel — Core Types and Interfaces
 * =========================================================
 * engine.hpp  |  v0.1.0  |  C++20
 *
 * Defines the core data structures and interface for the Aegis Gulf
 * AES-256-GCM encrypted compliance archival engine with SHA-256 HMAC
 * audit chain.
 *
 * Compile requirements:
 *   g++ -std=c++20 -lssl -lcrypto
 *   Requires: libssl-dev (OpenSSL 3.x)
 *
 * Author: Nvula Bontes — Lead Architect, Aegis Gulf
 *         Kimberley, Northern Cape, South Africa
 */

#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <concepts>
#include <cstdint>

#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <variant>

namespace aegis {

// ── Constants ────────────────────────────────────────────────────────────────

/// AES-256-GCM key size in bytes
inline constexpr std::size_t KEY_BYTES    = 32;

/// AES-GCM nonce (IV) size in bytes — 12 bytes is GCM standard
inline constexpr std::size_t NONCE_BYTES  = 12;

/// AES-GCM authentication tag size in bytes
inline constexpr std::size_t TAG_BYTES    = 16;

/// SHA-256 digest size in bytes
inline constexpr std::size_t HMAC_BYTES   = 32;

/// Genesis HMAC — all zeros, anchors the audit chain at entry #1
inline constexpr std::array<uint8_t, HMAC_BYTES> CHAIN_GENESIS = {};

// ── Concepts ─────────────────────────────────────────────────────────────────

/// Anything that can be viewed as a contiguous range of bytes
template <typename T>
concept ByteRange = requires(T t) {
    { std::as_bytes(std::span{t}) } -> std::convertible_to<std::span<const std::byte>>;
};

// ── Error types ───────────────────────────────────────────────────────────────

enum class KernelError {
    EncryptionFailed,
    DecryptionFailed,
    HmacFailed,
    ChainVerificationFailed,
    VaultEmpty,
    EntryNotFound,
    InvalidKey,
};

/**
 * Simple Result<T> type — compatible with C++20.
 * Holds either a value T or a KernelError.
 */
template <typename T>
struct Result {
    std::variant<T, KernelError> data;

    Result(T val) : data(std::move(val)) {}                        // NOLINT
    Result(KernelError e) : data(e) {}                             // NOLINT

    explicit operator bool() const noexcept {
        return std::holds_alternative<T>(data);
    }
    T&       operator*()        { return std::get<T>(data); }
    const T& operator*() const  { return std::get<T>(data); }
    T*       operator->()       { return &std::get<T>(data); }
    KernelError error() const   { return std::get<KernelError>(data); }
};

// Specialisation for void results
template <>
struct Result<void> {
    std::optional<KernelError> err;

    Result()                 : err(std::nullopt) {}                // success
    Result(KernelError e)    : err(e) {}                           // NOLINT
    explicit operator bool() const noexcept { return !err.has_value(); }
    KernelError error() const { return *err; }
};

// Helper to create an error result — mirrors std::unexpected
template <typename T>
Result<T> make_error(KernelError e) { return Result<T>(e); }

// ── Core data structures ──────────────────────────────────────────────────────

using KeyBytes   = std::array<uint8_t, KEY_BYTES>;
using NonceBytes = std::array<uint8_t, NONCE_BYTES>;
using HmacBytes  = std::array<uint8_t, HMAC_BYTES>;
using TagBytes   = std::array<uint8_t, TAG_BYTES>;

/**
 * An encrypted, HMAC-chained vault entry.
 *
 * Every entry in the Aegis Gulf vault is:
 *   1. AES-256-GCM encrypted with a unique random nonce
 *   2. Tagged with a SHA-256 HMAC that chains to the previous entry
 *
 * Tampering with any entry breaks the chain from that point forward.
 * This is the cryptographic foundation of POPIA Section 19 compliance.
 */
struct VaultEntry {
    /// Sequential identifier — starts at 1
    uint64_t entry_id;

    /// Unix timestamp (nanoseconds since epoch) when entry was archived
    uint64_t timestamp_ns;

    /// AES-256-GCM encrypted payload
    std::vector<uint8_t> ciphertext;

    /// GCM nonce (unique per entry — NEVER reused)
    NonceBytes nonce;

    /// GCM authentication tag (proves ciphertext integrity)
    TagBytes auth_tag;

    /// SHA-256 HMAC linking this entry to the previous (audit chain)
    HmacBytes chain_hmac;

    /// SHA-256 HMAC of the previous entry (chain anchor)
    HmacBytes prev_hmac;

    /// Plaintext metadata (event category, source system — NOT PII)
    std::string metadata_json;
};

/**
 * Result of a full vault chain verification.
 *
 * Returned by AegisKernel::verify_chain(). If valid is false,
 * broken_at_entry_id identifies the first corrupted entry.
 */
struct VerificationResult {
    bool          valid;
    uint64_t      entries_checked;
    std::optional<uint64_t> broken_at_entry_id;
    double        elapsed_ms;
    std::string   message;
};

/**
 * Live performance statistics for the kernel.
 */
struct KernelStats {
    uint64_t total_entries;
    uint64_t total_bytes_archived;
    double   uptime_seconds;
    uint64_t encrypt_ops;
    uint64_t hmac_ops;
};

// ── Kernel interface ─────────────────────────────────────────────────────────

/**
 * AegisKernel — the core compliance engine interface.
 *
 * Implementations:
 *   - AesChainingKernel (engine.cpp) — production AES-256-GCM kernel
 *
 * All methods are thread-safe.
 */
class AegisKernel {
public:
    virtual ~AegisKernel() = default;

    /**
     * Archive a compliance event.
     *
     * Encrypts the payload with AES-256-GCM using a fresh random nonce,
     * computes the SHA-256 HMAC chain link, and appends the entry to the
     * append-only vault.
     *
     * @param event_type  POPIA event category (e.g. "user_consent_captured")
     * @param payload_json  JSON-encoded event payload (PII — will be encrypted)
     * @param metadata_json Optional plaintext metadata (audit context)
     * @return The archived VaultEntry, or a KernelError
     */
    virtual Result<VaultEntry> archive(
        std::string_view event_type,
        std::string_view payload_json,
        std::string_view metadata_json = "{}"
    ) = 0;

    /**
     * Verify the integrity of the entire audit chain.
     *
     * Recomputes every HMAC from the genesis block forward. Any
     * single-bit modification to any ciphertext or metadata will
     * produce a mismatch, and broken_at_entry_id will identify
     * the exact corrupted entry.
     *
     * This is the cryptographic proof delivered to the Information
     * Regulator under POPIA Section 19.
     */
    virtual VerificationResult verify_chain() const = 0;

    /**
     * Decrypt an archived entry (authorised access only).
     *
     * In production this should require dual-authorisation (4-eyes
     * principle). The caller must hold the encryption key.
     */
    virtual Result<std::string> decrypt(const VaultEntry& entry) const = 0;

    /**
     * Return current vault and performance statistics.
     */
    virtual KernelStats stats() const = 0;

    /**
     * Export vault entries as JSON (for Regulator submission).
     * @param limit  Maximum number of entries to export (most recent)
     */
    virtual std::string export_json(std::size_t limit = 100) const = 0;
};

/**
 * Factory — create a production AES-256-GCM kernel.
 *
 * @param encryption_key  32-byte AES-256 key.
 *                        If empty, a cryptographically random key is generated.
 * @param hmac_key        32-byte HMAC key (separate from encryption key).
 *                        If empty, a cryptographically random key is generated.
 */
std::unique_ptr<AegisKernel> make_kernel(
    std::optional<KeyBytes> encryption_key = std::nullopt,
    std::optional<KeyBytes> hmac_key       = std::nullopt
);

} // namespace aegis
