#include "utils.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace secscan {

bool isFailureEvent(const EventType type) {
    return type == EventType::FailedPassword;
}

bool isSuccessEvent(const EventType type) {
    return type == EventType::AcceptedPassword || type == EventType::AcceptedPublicKey;
}

std::string toString(const EventType type) {
    switch (type) {
        case EventType::FailedPassword:
            return "FAILED_PASSWORD";
        case EventType::AcceptedPassword:
            return "ACCEPTED_PASSWORD";
        case EventType::AcceptedPublicKey:
            return "ACCEPTED_PUBLICKEY";
        default:
            return "UNSUPPORTED";
    }
}

std::string toString(const AlertType type) {
    switch (type) {
        case AlertType::BruteForce:
            return "BRUTE_FORCE";
        case AlertType::UsernameSpray:
            return "USERNAME_SPRAY";
        case AlertType::SuspiciousSuccess:
            return "SUSPICIOUS_SUCCESS";
        case AlertType::DenylistedActivity:
            return "DENYLISTED_ACTIVITY";
        default:
            return "UNKNOWN";
    }
}

std::string trim(const std::string& input) {
    std::size_t start = 0;
    while (start < input.size() && std::isspace(static_cast<unsigned char>(input[start])) != 0) {
        ++start;
    }

    std::size_t end = input.size();
    while (end > start && std::isspace(static_cast<unsigned char>(input[end - 1])) != 0) {
        --end;
    }

    return input.substr(start, end - start);
}

bool startsWith(const std::string& input, const std::string& prefix) {
    return input.size() >= prefix.size() && input.compare(0, prefix.size(), prefix) == 0;
}

std::vector<std::string> split(const std::string& input, const char delimiter) {
    std::vector<std::string> parts;
    std::stringstream stream(input);
    std::string item;
    while (std::getline(stream, item, delimiter)) {
        parts.push_back(item);
    }
    return parts;
}

std::optional<int> parseClockToMinute(const std::string& value) {
    const std::vector<std::string> parts = split(value, ':');
    if (parts.size() != 2) {
        return std::nullopt;
    }

    try {
        const int hour = std::stoi(parts[0]);
        const int minute = std::stoi(parts[1]);
        if (hour < 0 || hour > 23 || minute < 0 || minute > 59) {
            return std::nullopt;
        }
        return (hour * 60) + minute;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<int> parseTimestampMinute(const std::string& hhmmss) {
    const std::vector<std::string> parts = split(hhmmss, ':');
    if (parts.size() != 3) {
        return std::nullopt;
    }

    try {
        const int hour = std::stoi(parts[0]);
        const int minute = std::stoi(parts[1]);
        const int second = std::stoi(parts[2]);
        if (hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59) {
            return std::nullopt;
        }
        return (hour * 60) + minute;
    } catch (...) {
        return std::nullopt;
    }
}

bool inTimeWindow(const int minuteOfDay, const std::optional<int>& sinceMinute, const std::optional<int>& untilMinute) {
    if (!sinceMinute.has_value() && !untilMinute.has_value()) {
        return true;
    }

    if (minuteOfDay < 0) {
        return false;
    }

    if (sinceMinute.has_value() && !untilMinute.has_value()) {
        return minuteOfDay >= sinceMinute.value();
    }

    if (!sinceMinute.has_value() && untilMinute.has_value()) {
        return minuteOfDay <= untilMinute.value();
    }

    const int since = sinceMinute.value();
    const int until = untilMinute.value();
    if (since <= until) {
        return minuteOfDay >= since && minuteOfDay <= until;
    }

    return minuteOfDay >= since || minuteOfDay <= until;
}

std::vector<LogEvent> filterEventsByTime(const std::vector<LogEvent>& events, const QueryOptions& options) {
    if (!options.sinceMinute.has_value() && !options.untilMinute.has_value()) {
        return events;
    }

    std::vector<LogEvent> filtered;
    filtered.reserve(events.size());
    for (const LogEvent& event : events) {
        if (inTimeWindow(event.minuteOfDay, options.sinceMinute, options.untilMinute)) {
            filtered.push_back(event);
        }
    }
    return filtered;
}

std::string jsonEscape(const std::string& input) {
    std::ostringstream out;
    for (const char ch : input) {
        switch (ch) {
            case '\"':
                out << "\\\"";
                break;
            case '\\':
                out << "\\\\";
                break;
            case '\b':
                out << "\\b";
                break;
            case '\f':
                out << "\\f";
                break;
            case '\n':
                out << "\\n";
                break;
            case '\r':
                out << "\\r";
                break;
            case '\t':
                out << "\\t";
                break;
            default:
                out << ch;
                break;
        }
    }
    return out.str();
}

std::string join(const std::vector<std::string>& values, const std::string& delimiter) {
    if (values.empty()) {
        return {};
    }

    std::ostringstream out;
    for (std::size_t i = 0; i < values.size(); ++i) {
        out << values[i];
        if (i + 1 < values.size()) {
            out << delimiter;
        }
    }
    return out.str();
}

std::vector<std::string> loadIpListFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("could not open IP list file: " + path);
    }

    std::vector<std::string> ips;
    std::string line;
    while (std::getline(file, line)) {
        const std::string cleaned = trim(line);
        if (cleaned.empty() || startsWith(cleaned, "#")) {
            continue;
        }
        ips.push_back(cleaned);
    }
    return ips;
}

}  // namespace secscan
