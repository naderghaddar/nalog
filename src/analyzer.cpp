#include "analyzer.h"

#include <algorithm>
#include <unordered_map>
#include <unordered_set>

#include "utils.h"

namespace secscan {

LogAnalyzer::LogAnalyzer(std::vector<LogEvent> events)
    : events_(std::move(events)) {}

const std::vector<LogEvent>& LogAnalyzer::events() const {
    return events_;
}

std::vector<LogEvent> LogAnalyzer::failures() const {
    std::vector<LogEvent> out;
    out.reserve(events_.size());
    for (const LogEvent& event : events_) {
        if (isFailureEvent(event.eventType)) {
            out.push_back(event);
        }
    }
    return out;
}

std::vector<LogEvent> LogAnalyzer::successes() const {
    std::vector<LogEvent> out;
    out.reserve(events_.size());
    for (const LogEvent& event : events_) {
        if (isSuccessEvent(event.eventType)) {
            out.push_back(event);
        }
    }
    return out;
}

SummaryReport LogAnalyzer::summary(const ParseStats& stats) const {
    SummaryReport report;
    report.totalLinesRead = stats.totalLines;
    report.totalParsedSecurityEvents = events_.size();

    std::unordered_set<std::string> attackingIps;
    std::unordered_set<std::string> targetedUsers;

    for (const LogEvent& event : events_) {
        if (isFailureEvent(event.eventType)) {
            ++report.failedLoginCount;
            if (!event.ipAddress.empty()) {
                attackingIps.insert(event.ipAddress);
            }
            if (!event.username.empty()) {
                targetedUsers.insert(event.username);
            }
        } else if (isSuccessEvent(event.eventType)) {
            ++report.successfulLoginCount;
        }
    }

    report.uniqueAttackingIps = attackingIps.size();
    report.uniqueUsernamesTargeted = targetedUsers.size();
    return report;
}

std::vector<std::pair<std::string, std::size_t>> LogAnalyzer::topFailedIps(
    const std::size_t limit,
    const std::unordered_set<std::string>* allowlist
) const {
    std::unordered_map<std::string, std::size_t> counts;
    for (const LogEvent& event : events_) {
        if (!isFailureEvent(event.eventType) || event.ipAddress.empty()) {
            continue;
        }
        if (allowlist != nullptr && !allowlist->empty() && allowlist->count(event.ipAddress) > 0) {
            continue;
        }
        ++counts[event.ipAddress];
    }

    std::vector<std::pair<std::string, std::size_t>> ranked(counts.begin(), counts.end());
    std::sort(
        ranked.begin(),
        ranked.end(),
        [](const auto& lhs, const auto& rhs) {
            if (lhs.second != rhs.second) {
                return lhs.second > rhs.second;
            }
            return lhs.first < rhs.first;
        }
    );

    if (limit > 0 && ranked.size() > limit) {
        ranked.resize(limit);
    }
    return ranked;
}

std::vector<std::pair<std::string, std::size_t>> LogAnalyzer::topUsers(const std::size_t limit) const {
    std::unordered_map<std::string, std::size_t> counts;
    for (const LogEvent& event : events_) {
        if (event.username.empty()) {
            continue;
        }
        ++counts[event.username];
    }

    std::vector<std::pair<std::string, std::size_t>> ranked(counts.begin(), counts.end());
    std::sort(
        ranked.begin(),
        ranked.end(),
        [](const auto& lhs, const auto& rhs) {
            if (lhs.second != rhs.second) {
                return lhs.second > rhs.second;
            }
            return lhs.first < rhs.first;
        }
    );

    if (limit > 0 && ranked.size() > limit) {
        ranked.resize(limit);
    }
    return ranked;
}

std::vector<DetectionAlert> LogAnalyzer::detect(
    const DetectionConfig& config,
    const std::unordered_set<std::string>& allowlist,
    const std::unordered_set<std::string>& denylist
) const {
    std::unordered_map<std::string, std::size_t> failedByIp;
    std::unordered_map<std::string, std::unordered_set<std::string>> usersByIp;
    std::unordered_set<std::string> suspiciousSuccessIps;
    std::unordered_set<std::string> seenDenylistedIps;

    std::vector<LogEvent> orderedEvents = events_;
    std::sort(
        orderedEvents.begin(),
        orderedEvents.end(),
        [](const LogEvent& lhs, const LogEvent& rhs) {
            return lhs.lineNumber < rhs.lineNumber;
        }
    );

    for (const LogEvent& event : orderedEvents) {
        if (event.ipAddress.empty()) {
            continue;
        }

        if (denylist.count(event.ipAddress) > 0) {
            seenDenylistedIps.insert(event.ipAddress);
        }

        if (allowlist.count(event.ipAddress) > 0) {
            continue;
        }

        if (isFailureEvent(event.eventType)) {
            ++failedByIp[event.ipAddress];
            if (!event.username.empty()) {
                usersByIp[event.ipAddress].insert(event.username);
            }
            continue;
        }

        if (isSuccessEvent(event.eventType)) {
            const std::size_t failures = failedByIp[event.ipAddress];
            if (failures >= config.suspiciousSuccessFailureThreshold) {
                suspiciousSuccessIps.insert(event.ipAddress);
            }
        }
    }

    std::vector<DetectionAlert> alerts;
    for (const auto& item : failedByIp) {
        const std::string& ip = item.first;
        const std::size_t failures = item.second;
        const std::size_t userCount = usersByIp[ip].size();
        std::vector<std::string> users(usersByIp[ip].begin(), usersByIp[ip].end());
        std::sort(users.begin(), users.end());

        if (failures > config.bruteForceThreshold) {
            DetectionAlert alert;
            alert.type = AlertType::BruteForce;
            alert.ipAddress = ip;
            alert.failedAttempts = failures;
            alert.targetedUserCount = userCount;
            alert.users = users;
            alert.description = "possible brute-force behavior: failures above threshold";
            alerts.push_back(alert);
        }

        if (userCount >= config.sprayThreshold) {
            DetectionAlert alert;
            alert.type = AlertType::UsernameSpray;
            alert.ipAddress = ip;
            alert.failedAttempts = failures;
            alert.targetedUserCount = userCount;
            alert.users = users;
            alert.description = "possible username spray: many distinct usernames targeted";
            alerts.push_back(alert);
        }

        if (suspiciousSuccessIps.count(ip) > 0) {
            DetectionAlert alert;
            alert.type = AlertType::SuspiciousSuccess;
            alert.ipAddress = ip;
            alert.failedAttempts = failures;
            alert.targetedUserCount = userCount;
            alert.users = users;
            alert.description = "possible suspicious success: repeated failures followed by success";
            alerts.push_back(alert);
        }
    }

    for (const std::string& ip : seenDenylistedIps) {
        DetectionAlert alert;
        alert.type = AlertType::DenylistedActivity;
        alert.ipAddress = ip;
        alert.failedAttempts = failedByIp[ip];
        alert.targetedUserCount = usersByIp[ip].size();
        std::vector<std::string> users(usersByIp[ip].begin(), usersByIp[ip].end());
        std::sort(users.begin(), users.end());
        alert.users = users;
        alert.description = "denylisted IP observed in log";
        alerts.push_back(alert);
    }

    std::sort(
        alerts.begin(),
        alerts.end(),
        [](const DetectionAlert& lhs, const DetectionAlert& rhs) {
            if (lhs.failedAttempts != rhs.failedAttempts) {
                return lhs.failedAttempts > rhs.failedAttempts;
            }
            if (lhs.ipAddress != rhs.ipAddress) {
                return lhs.ipAddress < rhs.ipAddress;
            }
            return toString(lhs.type) < toString(rhs.type);
        }
    );

    return alerts;
}

}  // namespace secscan
