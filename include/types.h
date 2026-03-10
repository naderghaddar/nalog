#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace secscan {

enum class EventType {
    FailedPassword,
    AcceptedPassword,
    AcceptedPublicKey,
    Unsupported
};

enum class AlertType {
    BruteForce,
    UsernameSpray,
    SuspiciousSuccess,
    DenylistedActivity
};

struct LogEvent {
    std::string rawLine;
    std::string timestampText;
    std::string hostname;
    std::string process;
    EventType eventType{EventType::Unsupported};
    std::string username;
    std::string ipAddress;
    int port{-1};
    std::size_t lineNumber{0};
    int minuteOfDay{-1};
    bool valid{false};
};

struct ParseStats {
    std::size_t totalLines{0};
    std::size_t parsedEvents{0};
    std::size_t ignoredLines{0};
};

struct SummaryReport {
    std::size_t totalLinesRead{0};
    std::size_t totalParsedSecurityEvents{0};
    std::size_t failedLoginCount{0};
    std::size_t successfulLoginCount{0};
    std::size_t uniqueAttackingIps{0};
    std::size_t uniqueUsernamesTargeted{0};
};

struct DetectionConfig {
    std::size_t bruteForceThreshold{20};
    std::size_t sprayThreshold{5};
    std::size_t suspiciousSuccessFailureThreshold{5};
};

struct DetectionAlert {
    AlertType type{AlertType::BruteForce};
    std::string ipAddress;
    std::size_t failedAttempts{0};
    std::size_t targetedUserCount{0};
    std::vector<std::string> users;
    std::string description;
};

struct QueryOptions {
    std::size_t limit{0};
    bool json{false};
    std::optional<int> sinceMinute;
    std::optional<int> untilMinute;
    std::vector<std::string> allowlistIps;
    std::vector<std::string> denylistIps;
    DetectionConfig detectionConfig{};
    int watchIntervalSeconds{2};
};

}  // namespace secscan
