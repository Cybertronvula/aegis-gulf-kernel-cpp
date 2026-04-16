/**
 * Aegis Gulf Compliance Kernel — Breach Detection Engine
 * =======================================================
 * breach.hpp  |  v0.1.0  |  C++20
 *
 * Rule-based breach detection engine for POPIA Section 22 compliance.
 *
 * Detects breaches using configurable threshold rules applied to the
 * encrypted audit chain. When a breach is detected, the engine:
 *   1. Archives the breach event in the encrypted chain (Section 19)
 *   2. Generates a structured breach report (Section 22)
 *   3. Returns a BreachAlert for the notification workflow
 *
 * HONEST STATUS (v0.1.0):
 *   Rule-based detection: IMPLEMENTED (4 rules, fully configurable)
 *   ML-based detection:   PLANNED — Isolation Forest, Q1 2027
 *
 * This is exactly what clients receive during the Ignition PoC.
 * The rule engine is sufficient for POPIA Section 22 compliance
 * in most SME and mid-market deployments.
 *
 * Author: Nvula Bontes — Lead Architect, Aegis Gulf
 *         Kimberley, Northern Cape, South Africa
 */

#pragma once

#include "engine.hpp"

#include <atomic>
#include <chrono>
#include <deque>
#include <format>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace aegis {
namespace breach {

// ── Severity levels ───────────────────────────────────────────────────────────

enum class Severity { Low, Medium, High, Critical };

static std::string_view severity_name(Severity s) {
    switch (s) {
        case Severity::Low:      return "LOW";
        case Severity::Medium:   return "MEDIUM";
        case Severity::High:     return "HIGH";
        case Severity::Critical: return "CRITICAL";
    }
    return "UNKNOWN";
}

// ── Breach alert structure ────────────────────────────────────────────────────

/**
 * A breach alert — returned when a rule fires.
 *
 * In production, this triggers:
 *   1. Archival in the encrypted chain (Section 19)
 *   2. Regulator-format breach report generation
 *   3. Information Officer notification
 *   4. eServices portal submission workflow (Section 22)
 */
struct BreachAlert {
    std::string       alert_id;           // e.g. BREACH-2026-0001
    std::string       rule_name;          // Which rule triggered
    Severity          severity;
    std::string       detail;             // Human-readable description
    std::string       recommended_action; // What to do next
    std::string       popia_section;      // e.g. "Section 22"
    std::string       triggered_at;       // ISO 8601 timestamp
    bool              requires_notification = true; // Regulator notification required?

    std::string to_json() const {
        return std::format(
            R"({{"alert_id":"{}","rule_name":"{}","severity":"{}","detail":"{}","recommended_action":"{}","popia_section":"{}","triggered_at":"{}","requires_regulator_notification":{}}})",
            alert_id, rule_name, severity_name(severity),
            detail, recommended_action, popia_section,
            triggered_at, requires_notification ? "true" : "false"
        );
    }
};

// ── Rule configuration ────────────────────────────────────────────────────────

/**
 * Configuration for the rule engine.
 * All thresholds are configurable at runtime — no recompilation required.
 */
struct RuleConfig {
    // Rule 1: Bulk data export anomaly (POPIA S.22)
    bool     bulk_export_enabled    = true;
    uint32_t bulk_export_threshold  = 50;     // records in window
    uint32_t bulk_export_window_sec = 300;    // 5-minute window

    // Rule 2: Failed authentication rate (POPIA S.19 / S.22)
    bool     failed_auth_enabled    = true;
    uint32_t failed_auth_threshold  = 10;     // failures in window
    uint32_t failed_auth_window_sec = 60;     // 1-minute window

    // Rule 3: Off-hours access to PII (POPIA S.19)
    bool     off_hours_enabled      = true;
    uint8_t  off_hours_start        = 23;     // 23:00
    uint8_t  off_hours_end          = 5;      // 05:00

    // Rule 4: Chain integrity break — ALWAYS enabled, no threshold
    // Any SHA-256 HMAC chain break is an immediate Critical alert.

    // Breach alert counter (for ID generation)
    mutable uint64_t alert_counter{0};
};

// ── Event types the rule engine monitors ──────────────────────────────────────

struct AuditEvent {
    std::string  event_type;    // "pii_access", "failed_login", etc.
    std::string  actor_id;      // user ID or service account
    std::string  resource_id;   // what was accessed
    uint64_t     timestamp_ns;  // nanoseconds since epoch
    uint32_t     record_count;  // how many records accessed
};

// ── Rule engine ───────────────────────────────────────────────────────────────

class BreachDetectionEngine {
public:
    explicit BreachDetectionEngine(RuleConfig config = {})
        : config_(std::move(config)) {}

    /**
     * Ingest an audit event and check all active rules.
     *
     * Call this for every significant event:
     *   - "pii_access"    when a user reads personal information
     *   - "pii_export"    when records are exported
     *   - "failed_login"  when authentication fails
     *   - "admin_access"  when privileged access occurs
     *
     * @returns A BreachAlert if any rule fired, std::nullopt otherwise.
     */
    std::optional<BreachAlert> ingest(const AuditEvent& event) {
        std::unique_lock lock(mutex_);
        window_.push_back(event);
        prune_window();

        // Rule 1: Bulk export
        if (config_.bulk_export_enabled &&
            (event.event_type == "pii_access" || event.event_type == "pii_export"))
        {
            if (auto alert = check_bulk_export(event)) return alert;
        }

        // Rule 2: Failed authentication
        if (config_.failed_auth_enabled && event.event_type == "failed_login") {
            if (auto alert = check_failed_auth(event)) return alert;
        }

        // Rule 3: Off-hours access
        if (config_.off_hours_enabled &&
            (event.event_type == "pii_access" || event.event_type == "pii_export"))
        {
            if (auto alert = check_off_hours(event)) return alert;
        }

        return std::nullopt;
    }

    /**
     * Rule 4: Chain integrity check.
     *
     * Call this against a running AegisKernel. A broken chain is always
     * a Critical breach — no threshold, no window, immediate alert.
     *
     * @param chain_result  The result of kernel.verify_chain()
     */
    std::optional<BreachAlert> check_chain_integrity(
        const VerificationResult& chain_result) const
    {
        if (chain_result.valid) return std::nullopt;

        return make_alert(
            "chain_integrity_break",
            Severity::Critical,
            std::format(
                "SHA-256 HMAC audit chain BROKEN at entry ID {}. "
                "One or more log entries have been modified, deleted, or inserted. "
                "This is a definitive data integrity breach. "
                "Checked {} entries in {:.2f}ms.",
                chain_result.broken_at_entry_id.value_or(0),
                chain_result.entries_checked,
                chain_result.elapsed_ms),
            "Immediately initiate Section 22 breach notification workflow. "
            "Notify the Information Regulator via eServices portal. "
            "Notify affected data subjects. "
            "Preserve all evidence — do not attempt to repair the chain manually.",
            "Section 19 — Tamper Evidence / Section 22 — Breach Notification",
            true
        );
    }

    /**
     * Generate a Regulator-format breach report as JSON.
     * This is the document submitted to the Information Regulator.
     */
    std::string generate_breach_report(const BreachAlert& alert,
                                       std::string_view org_name,
                                       std::string_view io_name) const
    {
        std::string r;
        r  = "{";
        r += "\"report_type\":\"POPIA_Breach_Notification\",";
        r += "\"regulator\":\"Information Regulator of South Africa\",";
        r += "\"submission_method\":\"eServices Portal (April 2025)\",";
        r += "\"responsible_party\":\"" + std::string(org_name) + "\",";
        r += "\"information_officer\":\"" + std::string(io_name) + "\",";
        r += "\"breach_alert\":" + alert.to_json() + ",";
        r += "\"popia_sections\":[\"Section 19\",\"Section 22\"],";
        r += "\"status\":\"Pending IO approval - submit to Regulator without unreasonable delay\"";
        r += "}";
        return r;
    }


    /// Return all events in the current detection window (for audit purposes)
    std::vector<AuditEvent> current_window() const {
        std::unique_lock lock(mutex_);
        return std::vector<AuditEvent>(window_.begin(), window_.end());
    }

    const RuleConfig& config() const { return config_; }
    RuleConfig& config() { return config_; }

private:
    RuleConfig               config_;
    std::deque<AuditEvent>   window_;
    mutable std::mutex       mutex_;
    mutable std::atomic<uint64_t> alert_counter_{0};

    // ── Internal helpers ────────────────────────────────────────────────────

    void prune_window() {
        // Keep only events within the longest configured window
        const uint32_t max_window = std::max(
            config_.bulk_export_window_sec,
            config_.failed_auth_window_sec
        );
        const uint64_t cutoff_ns = now_ns() - static_cast<uint64_t>(max_window) * 1'000'000'000ULL;
        while (!window_.empty() && window_.front().timestamp_ns < cutoff_ns)
            window_.pop_front();
    }

    std::optional<BreachAlert> check_bulk_export(const AuditEvent& event) {
        const uint64_t window_ns = static_cast<uint64_t>(config_.bulk_export_window_sec) * 1'000'000'000ULL;
        const uint64_t from_ns   = now_ns() - window_ns;

        uint32_t total_records = 0;
        for (const auto& e : window_) {
            if (e.timestamp_ns < from_ns) continue;
            if (e.event_type == "pii_access" || e.event_type == "pii_export")
                total_records += e.record_count;
        }

        if (total_records < config_.bulk_export_threshold) return std::nullopt;

        return make_alert(
            "bulk_data_export_anomaly",
            Severity::High,
            std::format(
                "Bulk data export anomaly detected. "
                "{} records accessed/exported within a {}-second window by actor '{}'. "
                "Threshold: {} records. Exceeded by {} records.",
                total_records, config_.bulk_export_window_sec,
                event.actor_id, config_.bulk_export_threshold,
                total_records - config_.bulk_export_threshold),
            "Immediately review the export logs. If not authorised, initiate Section 22 "
            "breach notification. Suspend the actor account pending investigation.",
            "Section 22 — Breach Notification",
            true
        );
    }

    std::optional<BreachAlert> check_failed_auth(const AuditEvent& event) {
        const uint64_t window_ns = static_cast<uint64_t>(config_.failed_auth_window_sec) * 1'000'000'000ULL;
        const uint64_t from_ns   = now_ns() - window_ns;

        uint32_t failures = 0;
        for (const auto& e : window_) {
            if (e.timestamp_ns < from_ns) continue;
            if (e.event_type == "failed_login" && e.actor_id == event.actor_id)
                ++failures;
        }

        if (failures < config_.failed_auth_threshold) return std::nullopt;

        return make_alert(
            "failed_authentication_rate",
            Severity::Medium,
            std::format(
                "Failed authentication rate alert. "
                "{} failed login attempts against account '{}' within {} seconds. "
                "Threshold: {}. Potential brute-force or credential stuffing attack.",
                failures, event.actor_id,
                config_.failed_auth_window_sec, config_.failed_auth_threshold),
            "Lock the affected account immediately. Review source IP addresses. "
            "Check whether any login succeeded after failures — if so, treat as breach.",
            "Section 19 — Security Safeguards",
            false  // Notification not required until breach confirmed
        );
    }

    std::optional<BreachAlert> check_off_hours(const AuditEvent& event) {
        const auto t  = std::chrono::system_clock::now();
        const auto tt = std::chrono::system_clock::to_time_t(t);
        const auto* tm_ptr = std::localtime(&tt);
        const int hour = tm_ptr->tm_hour;

        const bool is_off_hours = (config_.off_hours_start <= config_.off_hours_end)
            ? (hour >= config_.off_hours_start && hour < config_.off_hours_end)
            : (hour >= config_.off_hours_start || hour < config_.off_hours_end);

        if (!is_off_hours) return std::nullopt;

        return make_alert(
            "off_hours_pii_access",
            Severity::Medium,
            std::format(
                "Off-hours PII access detected. "
                "Actor '{}' accessed/exported personal information at {:02d}:00 "
                "(monitored window: {:02d}:00–{:02d}:00). "
                "Resource: {}.",
                event.actor_id, hour,
                config_.off_hours_start, config_.off_hours_end,
                event.resource_id),
            "Verify the access was authorised. Contact the account holder. "
            "If access was not authorised, initiate breach investigation.",
            "Section 19 — Security Safeguards",
            false  // Monitor — confirm breach before notifying Regulator
        );
    }

    BreachAlert make_alert(
        std::string_view rule_name,
        Severity         severity,
        std::string      detail,
        std::string      action,
        std::string      section,
        bool             notify
    ) const {
        const uint64_t n = ++alert_counter_;

        // Format current time as ISO 8601
        const auto now = std::chrono::system_clock::now();
        const auto t   = std::chrono::system_clock::to_time_t(now);
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));

        BreachAlert alert;
        alert.alert_id              = std::format("BREACH-2026-{:04d}", n);
        alert.rule_name             = std::string(rule_name);
        alert.severity              = severity;
        alert.detail                = std::move(detail);
        alert.recommended_action    = std::move(action);
        alert.popia_section         = std::move(section);
        alert.triggered_at          = std::string(buf);
        alert.requires_notification = notify;
        return alert;
    }

    static uint64_t now_ns() noexcept {
        using namespace std::chrono;
        return static_cast<uint64_t>(
            duration_cast<nanoseconds>(system_clock::now().time_since_epoch()).count());
    }
};

} // namespace breach
} // namespace aegis
