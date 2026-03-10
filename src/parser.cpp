#include "parser.h"

#include <fstream>
#include <sstream>
#include <stdexcept>

#include "utils.h"

namespace secscan {
namespace {

bool parseUserIpPort(
    std::string payload,
    std::string& username,
    std::string& ipAddress,
    int& port
) {
    if (startsWith(payload, "invalid user ")) {
        payload = payload.substr(std::string("invalid user ").size());
    }

    const std::size_t fromPos = payload.find(" from ");
    if (fromPos == std::string::npos) {
        return false;
    }

    username = trim(payload.substr(0, fromPos));
    if (username.empty()) {
        return false;
    }

    std::string afterFrom = payload.substr(fromPos + std::string(" from ").size());
    const std::size_t portPos = afterFrom.find(" port ");
    if (portPos == std::string::npos) {
        return false;
    }

    ipAddress = trim(afterFrom.substr(0, portPos));
    if (ipAddress.empty()) {
        return false;
    }

    afterFrom = afterFrom.substr(portPos + std::string(" port ").size());
    const std::size_t portEnd = afterFrom.find(' ');
    const std::string portText = portEnd == std::string::npos ? afterFrom : afterFrom.substr(0, portEnd);

    try {
        port = std::stoi(portText);
    } catch (...) {
        return false;
    }

    return port >= 0;
}

}  // namespace

std::optional<LogEvent> AuthLogParser::parseLine(const std::string& rawLine, const std::size_t lineNumber) const {
    if (trim(rawLine).empty()) {
        return std::nullopt;
    }

    std::istringstream stream(rawLine);
    std::string month;
    std::string day;
    std::string timestamp;
    std::string hostname;
    std::string processToken;

    if (!(stream >> month >> day >> timestamp >> hostname >> processToken)) {
        return std::nullopt;
    }

    if (processToken.empty() || processToken.back() != ':') {
        return std::nullopt;
    }

    const std::string process = processToken.substr(0, processToken.size() - 1);
    if (!startsWith(process, "sshd")) {
        return std::nullopt;
    }

    std::string message;
    std::getline(stream, message);
    message = trim(message);

    LogEvent event;
    event.rawLine = rawLine;
    event.timestampText = month + " " + day + " " + timestamp;
    event.hostname = hostname;
    event.process = process;
    event.lineNumber = lineNumber;
    if (const std::optional<int> minute = parseTimestampMinute(timestamp); minute.has_value()) {
        event.minuteOfDay = minute.value();
    }

    if (startsWith(message, "Failed password for ")) {
        event.eventType = EventType::FailedPassword;
        std::string payload = message.substr(std::string("Failed password for ").size());
        if (!parseUserIpPort(payload, event.username, event.ipAddress, event.port)) {
            return std::nullopt;
        }
    } else if (startsWith(message, "Accepted password for ")) {
        event.eventType = EventType::AcceptedPassword;
        std::string payload = message.substr(std::string("Accepted password for ").size());
        if (!parseUserIpPort(payload, event.username, event.ipAddress, event.port)) {
            return std::nullopt;
        }
    } else if (startsWith(message, "Accepted publickey for ")) {
        event.eventType = EventType::AcceptedPublicKey;
        std::string payload = message.substr(std::string("Accepted publickey for ").size());
        if (!parseUserIpPort(payload, event.username, event.ipAddress, event.port)) {
            return std::nullopt;
        }
    } else {
        return std::nullopt;
    }

    event.valid = true;
    return event;
}

std::vector<LogEvent> AuthLogParser::parseFile(const std::string& path, ParseStats& stats) const {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("could not open log file: " + path);
    }

    std::vector<LogEvent> events;
    std::string line;
    std::size_t lineNumber = 0;
    while (std::getline(file, line)) {
        ++lineNumber;
        ++stats.totalLines;
        const std::optional<LogEvent> parsed = parseLine(line, lineNumber);
        if (!parsed.has_value()) {
            ++stats.ignoredLines;
            continue;
        }
        ++stats.parsedEvents;
        events.push_back(parsed.value());
    }

    return events;
}

}  // namespace secscan
