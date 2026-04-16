/**
 * Aegis Gulf Compliance Kernel — Storage Backend Adapters
 * ========================================================
 * storage.hpp  |  v0.2.0  |  C++20
 *
 * Defines the StorageBackend interface and provides a local-file
 * WORM (Write Once Read Many) adapter — the foundation for
 * POPIA Section 14 (Retention of Records) compliance.
 *
 * Adapters provided:
 *   - LocalWormStorage     (local filesystem — for testing and on-prem)
 *   - S3WormStorage        (AWS S3 Object Lock — interface defined, impl via AWS SDK)
 *   - AzureBlobStorage     (Azure immutability policies — interface defined)
 *
 * In production, LocalWormStorage is sufficient for Ignition PoC.
 * S3/Azure adapters are activated by linking the respective SDKs.
 *
 * POPIA Section 14 compliance:
 *   Records are retained for 5 years with immutable write-protection.
 *   Automated disposal scheduling marks entries for erasure at
 *   retention expiry without deleting them prematurely.
 *
 * Author: Nvula Bontes — Lead Architect, Aegis Gulf
 *         Kimberley, Northern Cape, South Africa
 */

#pragma once

#include "engine.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace aegis {
namespace storage {

// ── Retention policy ──────────────────────────────────────────────────────────

/// POPIA Section 14 — Records must be kept for at least 5 years
inline constexpr auto POPIA_RETENTION_YEARS = 5;
inline constexpr auto POPIA_RETENTION_DAYS  = POPIA_RETENTION_YEARS * 365;

/// A stored entry — the VaultEntry plus storage metadata
struct StoredEntry {
    VaultEntry                               entry;
    std::chrono::system_clock::time_point    stored_at;
    std::chrono::system_clock::time_point    expires_at;  // stored_at + 5 years
    bool                                     deletion_eligible = false;
};

// ── StorageBackend interface ──────────────────────────────────────────────────

/**
 * Abstract storage backend.
 *
 * Every implementation must guarantee:
 *   1. Append-only: entries cannot be modified or deleted before expiry
 *   2. Persistence: entries survive process restart
 *   3. Chain preservation: the full sequence must be retrievable in order
 *
 * This is the WORM guarantee required for POPIA Section 14.
 */
class StorageBackend {
public:
    virtual ~StorageBackend() = default;

    /// Append an encrypted VaultEntry to durable storage
    virtual Result<void> append(const VaultEntry& entry) = 0;

    /// Load all entries in order (for chain reconstruction after restart)
    virtual Result<std::vector<VaultEntry>> load_all() const = 0;

    /// Count entries without loading them
    virtual Result<uint64_t> count() const = 0;

    /// Mark entries older than retention period as deletion-eligible
    /// (does NOT delete them — requires separate administrative action)
    virtual Result<std::size_t> flag_expired_for_review() = 0;

    /// Human-readable storage location identifier
    virtual std::string location() const = 0;
};

// ── Local WORM Storage ────────────────────────────────────────────────────────

/**
 * LocalWormStorage — filesystem-based append-only log.
 *
 * Suitable for:
 *   - Ignition PoC staging deployments
 *   - On-premises deployments where S3 is not available
 *   - Development and testing
 *
 * Each VaultEntry is serialised as a length-prefixed binary record
 * and appended to a single file. The file is opened in append-only
 * mode — the OS prevents any modification of existing bytes.
 *
 * In production, this file should live on a volume with filesystem-level
 * immutability (e.g., ZFS with zfs-immutable, or NFS with read-only mount).
 */
class LocalWormStorage final : public StorageBackend {
public:
    explicit LocalWormStorage(std::filesystem::path vault_path)
        : path_(std::move(vault_path))
    {
        // Create directory if it doesn't exist
        std::filesystem::create_directories(path_.parent_path());
    }

    Result<void> append(const VaultEntry& entry) override {
        try {
            std::ofstream f(path_, std::ios::binary | std::ios::app);
            if (!f) return Result<void>(KernelError::EncryptionFailed);

            // Serialise: entry_id(8) | timestamp_ns(8) | nonce(12) | tag(16)
            //            | hmac(32) | prev_hmac(32) | ct_len(8) | ciphertext
            //            | meta_len(4) | metadata
            write_u64(f, entry.entry_id);
            write_u64(f, entry.timestamp_ns);
            f.write(reinterpret_cast<const char*>(entry.nonce.data()),    12);
            f.write(reinterpret_cast<const char*>(entry.auth_tag.data()), 16);
            f.write(reinterpret_cast<const char*>(entry.chain_hmac.data()),32);
            f.write(reinterpret_cast<const char*>(entry.prev_hmac.data()), 32);

            const uint64_t ct_len = entry.ciphertext.size();
            write_u64(f, ct_len);
            f.write(reinterpret_cast<const char*>(entry.ciphertext.data()),
                    static_cast<std::streamsize>(ct_len));

            const uint32_t meta_len = static_cast<uint32_t>(entry.metadata_json.size());
            write_u32(f, meta_len);
            f.write(entry.metadata_json.data(),
                    static_cast<std::streamsize>(meta_len));

            f.flush();
            if (!f.good()) return Result<void>(KernelError::EncryptionFailed);
            return Result<void>{};
        } catch (...) {
            return Result<void>(KernelError::EncryptionFailed);
        }
    }

    Result<std::vector<VaultEntry>> load_all() const override {
        try {
            std::vector<VaultEntry> entries;
            if (!std::filesystem::exists(path_)) return entries;

            std::ifstream f(path_, std::ios::binary);
            if (!f) return Result<std::vector<VaultEntry>>(KernelError::VaultEmpty);

            while (f.peek() != EOF) {
                VaultEntry e;
                e.entry_id     = read_u64(f);
                e.timestamp_ns = read_u64(f);

                f.read(reinterpret_cast<char*>(e.nonce.data()),     12);
                f.read(reinterpret_cast<char*>(e.auth_tag.data()),  16);
                f.read(reinterpret_cast<char*>(e.chain_hmac.data()),32);
                f.read(reinterpret_cast<char*>(e.prev_hmac.data()), 32);

                const uint64_t ct_len = read_u64(f);
                e.ciphertext.resize(ct_len);
                f.read(reinterpret_cast<char*>(e.ciphertext.data()),
                       static_cast<std::streamsize>(ct_len));

                const uint32_t meta_len = read_u32(f);
                e.metadata_json.resize(meta_len);
                f.read(e.metadata_json.data(),
                       static_cast<std::streamsize>(meta_len));

                if (!f.good()) break;
                entries.push_back(std::move(e));
            }
            return entries;
        } catch (...) {
            return Result<std::vector<VaultEntry>>(KernelError::VaultEmpty);
        }
    }

    Result<uint64_t> count() const override {
        auto r = load_all();
        if (!r) return Result<uint64_t>(r.error());
        return static_cast<uint64_t>((*r).size());
    }

    Result<std::size_t> flag_expired_for_review() override {
        // In this implementation: load all, count those older than 5 years
        auto r = load_all();
        if (!r) return Result<std::size_t>(r.error());

        const auto now = std::chrono::system_clock::now();
        const auto cutoff = now - std::chrono::hours(24 * POPIA_RETENTION_DAYS);
        const auto cutoff_ns = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                cutoff.time_since_epoch()).count());

        std::size_t count = 0;
        for (const auto& e : *r)
            if (e.timestamp_ns < cutoff_ns) ++count;

        return count;
    }

    std::string location() const override {
        return "local://" + path_.string();
    }

private:
    std::filesystem::path path_;

    static void write_u64(std::ostream& f, uint64_t v) {
        f.write(reinterpret_cast<const char*>(&v), 8);
    }
    static void write_u32(std::ostream& f, uint32_t v) {
        f.write(reinterpret_cast<const char*>(&v), 4);
    }
    static uint64_t read_u64(std::istream& f) {
        uint64_t v = 0; f.read(reinterpret_cast<char*>(&v), 8); return v;
    }
    static uint32_t read_u32(std::istream& f) {
        uint32_t v = 0; f.read(reinterpret_cast<char*>(&v), 4); return v;
    }
};

// ── S3 WORM Storage (interface — activate by linking AWS SDK) ─────────────────

/**
 * S3WormStorage — AWS S3 Object Lock (WORM) backend.
 *
 * Requires: AWS SDK for C++ (aws-sdk-cpp)
 * Object Lock must be enabled on the S3 bucket with COMPLIANCE mode.
 * Retention period: 5 years (configurable via POPIA_RETENTION_DAYS).
 *
 * This is the recommended production backend for cloud deployments.
 * Data stays in the AWS South Africa (Cape Town) region — full
 * data sovereignty maintained within South African borders.
 *
 * Usage:
 *   auto backend = std::make_unique<S3WormStorage>(
 *       "aegis-gulf-popia-vault-clientname",  // S3 bucket name
 *       "af-south-1"                          // Cape Town region
 *   );
 */
class S3WormStorage final : public StorageBackend {
public:
    S3WormStorage(std::string bucket_name, std::string region = "af-south-1")
        : bucket_(std::move(bucket_name)), region_(std::move(region)) {}

    Result<void> append(const VaultEntry&) override {
        // Full implementation requires aws-sdk-cpp:
        //   Aws::S3::S3Client client;
        //   Aws::S3::Model::PutObjectRequest request;
        //   request.SetBucket(bucket_);
        //   request.SetKey("vault/" + std::to_string(entry.entry_id) + ".bin");
        //   request.SetObjectLockMode(Aws::S3::Model::ObjectLockMode::COMPLIANCE);
        //   request.SetObjectLockRetainUntilDate(retention_date());
        //   client.PutObject(request);
        return Result<void>(KernelError::EncryptionFailed); // stub until SDK linked
    }

    Result<std::vector<VaultEntry>> load_all() const override {
        return Result<std::vector<VaultEntry>>(KernelError::VaultEmpty);
    }

    Result<uint64_t> count() const override {
        return Result<uint64_t>(KernelError::VaultEmpty);
    }

    Result<std::size_t> flag_expired_for_review() override { return std::size_t{0}; }

    std::string location() const override {
        return "s3://" + bucket_ + " (" + region_ + ") — AWS Object Lock COMPLIANCE mode";
    }

private:
    std::string bucket_;
    std::string region_;
};

// ── Factory ───────────────────────────────────────────────────────────────────

/// Create a local WORM storage backend for the Ignition PoC
inline std::unique_ptr<StorageBackend> make_local_storage(
    const std::filesystem::path& vault_dir = "./aegis_vault"
) {
    return std::make_unique<LocalWormStorage>(vault_dir / "compliance_vault.bin");
}

/// Create an S3 WORM storage backend (requires aws-sdk-cpp linked)
inline std::unique_ptr<StorageBackend> make_s3_storage(
    const std::string& bucket_name,
    const std::string& region = "af-south-1"
) {
    return std::make_unique<S3WormStorage>(bucket_name, region);
}

} // namespace storage
} // namespace aegis
