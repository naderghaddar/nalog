#include "cli.h"

#include <chrono>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "analyzer.h"
#include "parser.h"
#include "types.h"
#include "utils.h"

namespace secscan {
namespace {

constexpr const char* kProjectDescription =
    "A C++ CLI tool for analyzing Linux authentication logs and detecting suspicious SSH activity.";

bool isCommand(const std::string& value) {
    static const std::unordered_set<std::string> kCommands = {
        "failures",
        "successes",
        "summary",
        "top-ips",
        "top-users",
        "detect",
        "report",
        "watch"
    };
    return kCommands.count(value) > 0;
}

void printGeneralHelp() {
    std::cout << "secscan - Linux SSH auth log analyzer\n\n";
    std::cout << kProjectDescription << "\n\n";
    std::cout << "Usage:\n";
    std::cout << "  secscan <command> <logfile> [options]\n";
    std::cout << "  secscan --help\n\n";
    std::cout << "Commands:\n";
    std::cout << "  failures   list failed SSH login events\n";
    std::cout << "  successes  list successful SSH login events\n";
    std::cout << "  summary    print totals and basic security stats\n";
    std::cout << "  top-ips    show top IPs by failed attempts\n";
    std::cout << "  top-users  show top usernames seen in events\n";
    std::cout << "  detect     run brute-force/spray/suspicious-success rules\n";
    std::cout << "  report     print incident-style summary and detections\n";
    std::cout << "  watch      monitor a file and print new events/alerts\n\n";
    std::cout << "Options:\n";
    std::cout << "  --limit N                          max rows/alerts to display\n";
    std::cout << "  --json                             output machine-readable JSON\n";
    std::cout << "  --since HH:MM                      include events at or after time\n";
    std::cout << "  --until HH:MM                      include events at or before time\n";
    std::cout << "  --bruteforce-threshold N           detect threshold (default: 20)\n";
    std::cout << "  --spray-threshold N                detect threshold (default: 5)\n";
    std::cout << "  --suspicious-failure-threshold N   detect threshold (default: 5)\n";
    std::cout << "  --allowlist FILE                   ignore listed IPs for detections\n";
    std::cout << "  --denylist FILE                    flag listed IPs when observed\n";
    std::cout << "  --watch-interval N                 seconds between watch polls\n";
}

void printCommandHelp(const std::string& command) {
    std::cout << "Usage: secscan " << command << " <logfile> [options]\n";
}

bool parseUnsigned(const std::string& value, std::size_t& out) {
    try {
        const unsigned long long parsed = std::stoull(value);
        out = static_cast<std::size_t>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

bool parsePositiveInt(const std::string& value, int& out) {
    try {
        const int parsed = std::stoi(value);
        if (parsed <= 0) {
            return false;
        }
        out = parsed;
        return true;
    } catch (...) {
        return false;
    }
}

struct ParsedInput {
    std::string command;
    std::string logFile;
    QueryOptions options;
    bool showHelp{false};
    bool commandHelp{false};
    std::string error;
};

ParsedInput parseArgs(const int argc, char** argv) {
    ParsedInput result;
    if (argc < 2) {
        result.showHelp = true;
        return result;
    }

    result.command = argv[1];
    if (result.command == "--help" || result.command == "-h" || result.command == "help") {
        result.showHelp = true;
        return result;
    }

    if (!isCommand(result.command)) {
        result.error = "unsupported command: " + result.command;
        return result;
    }

    if (argc < 3) {
        result.error = "missing log file path";
        return result;
    }

    if (std::string(argv[2]) == "--help") {
        result.commandHelp = true;
        return result;
    }

    result.logFile = argv[2];

    for (int i = 3; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help") {
            result.commandHelp = true;
            return result;
        }

        if (arg == "--json") {
            result.options.json = true;
            continue;
        }

        if (arg == "--limit") {
            if (i + 1 >= argc) {
                result.error = "--limit requires a value";
                return result;
            }
            if (!parseUnsigned(argv[i + 1], result.options.limit)) {
                result.error = "--limit must be a non-negative integer";
                return result;
            }
            ++i;
            continue;
        }

        if (arg == "--since") {
            if (i + 1 >= argc) {
                result.error = "--since requires HH:MM";
                return result;
            }
            const std::optional<int> minute = parseClockToMinute(argv[i + 1]);
            if (!minute.has_value()) {
                result.error = "invalid --since value, expected HH:MM";
                return result;
            }
            result.options.sinceMinute = minute;
            ++i;
            continue;
        }

        if (arg == "--until") {
            if (i + 1 >= argc) {
                result.error = "--until requires HH:MM";
                return result;
            }
            const std::optional<int> minute = parseClockToMinute(argv[i + 1]);
            if (!minute.has_value()) {
                result.error = "invalid --until value, expected HH:MM";
                return result;
            }
            result.options.untilMinute = minute;
            ++i;
            continue;
        }

        if (arg == "--bruteforce-threshold") {
            if (i + 1 >= argc) {
                result.error = "--bruteforce-threshold requires a value";
                return result;
            }
            std::size_t threshold = 0;
            if (!parseUnsigned(argv[i + 1], threshold)) {
                result.error = "--bruteforce-threshold must be a non-negative integer";
                return result;
            }
            result.options.detectionConfig.bruteForceThreshold = threshold;
            ++i;
            continue;
        }

        if (arg == "--spray-threshold") {
            if (i + 1 >= argc) {
                result.error = "--spray-threshold requires a value";
                return result;
            }
            std::size_t threshold = 0;
            if (!parseUnsigned(argv[i + 1], threshold)) {
                result.error = "--spray-threshold must be a non-negative integer";
                return result;
            }
            result.options.detectionConfig.sprayThreshold = threshold;
            ++i;
            continue;
        }

        if (arg == "--suspicious-failure-threshold") {
            if (i + 1 >= argc) {
                result.error = "--suspicious-failure-threshold requires a value";
                return result;
            }
            std::size_t threshold = 0;
            if (!parseUnsigned(argv[i + 1], threshold)) {
                result.error = "--suspicious-failure-threshold must be a non-negative integer";
                return result;
            }
            result.options.detectionConfig.suspiciousSuccessFailureThreshold = threshold;
            ++i;
            continue;
        }

        if (arg == "--allowlist") {
            if (i + 1 >= argc) {
                result.error = "--allowlist requires a file path";
                return result;
            }
            try {
                result.options.allowlistIps = loadIpListFile(argv[i + 1]);
            } catch (const std::exception& ex) {
                result.error = ex.what();
                return result;
            }
            ++i;
            continue;
        }

        if (arg == "--denylist") {
            if (i + 1 >= argc) {
                result.error = "--denylist requires a file path";
                return result;
            }
            try {
                result.options.denylistIps = loadIpListFile(argv[i + 1]);
            } catch (const std::exception& ex) {
                result.error = ex.what();
                return result;
            }
            ++i;
            continue;
        }

        if (arg == "--watch-interval") {
            if (i + 1 >= argc) {
                result.error = "--watch-interval requires a value";
                return result;
            }
            if (!parsePositiveInt(argv[i + 1], result.options.watchIntervalSeconds)) {
                result.error = "--watch-interval must be a positive integer";
                return result;
            }
            ++i;
            continue;
        }

        result.error = "unknown option: " + arg;
        return result;
    }

    return result;
}

std::vector<LogEvent> limitEvents(std::vector<LogEvent> events, const std::size_t limit) {
    if (limit > 0 && events.size() > limit) {
        events.resize(limit);
    }
    return events;
}

std::vector<DetectionAlert> limitAlerts(std::vector<DetectionAlert> alerts, const std::size_t limit) {
    if (limit > 0 && alerts.size() > limit) {
        alerts.resize(limit);
    }
    return alerts;
}

template <typename T>
void printJsonArray(const std::vector<T>& values, const std::function<void(const T&, std::size_t)>& printer) {
    std::cout << "[";
    for (std::size_t i = 0; i < values.size(); ++i) {
        printer(values[i], i);
        if (i + 1 < values.size()) {
            std::cout << ",";
        }
    }
    std::cout << "]\n";
}

void printEventsHuman(const std::vector<LogEvent>& events) {
    if (events.empty()) {
        std::cout << "No matching events found.\n";
        return;
    }

    for (const LogEvent& event : events) {
        std::cout
            << "[" << toString(event.eventType) << "] "
            << "line=" << event.lineNumber
            << " time=\"" << event.timestampText << "\""
            << " host=" << event.hostname
            << " user=" << event.username
            << " ip=" << event.ipAddress
            << " port=" << event.port
            << "\n";
    }
}

void printEventsJson(const std::vector<LogEvent>& events) {
    printJsonArray<LogEvent>(
        events,
        [](const LogEvent& event, std::size_t) {
            std::cout
                << "{"
                << "\"line\":" << event.lineNumber << ","
                << "\"timestamp\":\"" << jsonEscape(event.timestampText) << "\","
                << "\"host\":\"" << jsonEscape(event.hostname) << "\","
                << "\"process\":\"" << jsonEscape(event.process) << "\","
                << "\"event_type\":\"" << jsonEscape(toString(event.eventType)) << "\","
                << "\"username\":\"" << jsonEscape(event.username) << "\","
                << "\"ip_address\":\"" << jsonEscape(event.ipAddress) << "\","
                << "\"port\":" << event.port
                << "}";
        }
    );
}

void printSummaryHuman(const SummaryReport& report) {
    std::cout << "Summary\n";
    std::cout << "-------\n";
    std::cout << "Total lines read: " << report.totalLinesRead << "\n";
    std::cout << "Total parsed security events: " << report.totalParsedSecurityEvents << "\n";
    std::cout << "Failed login count: " << report.failedLoginCount << "\n";
    std::cout << "Successful login count: " << report.successfulLoginCount << "\n";
    std::cout << "Unique attacking IPs: " << report.uniqueAttackingIps << "\n";
    std::cout << "Unique usernames targeted: " << report.uniqueUsernamesTargeted << "\n";
}

void printSummaryJson(const SummaryReport& report) {
    std::cout
        << "{"
        << "\"total_lines_read\":" << report.totalLinesRead << ","
        << "\"total_parsed_security_events\":" << report.totalParsedSecurityEvents << ","
        << "\"failed_login_count\":" << report.failedLoginCount << ","
        << "\"successful_login_count\":" << report.successfulLoginCount << ","
        << "\"unique_attacking_ips\":" << report.uniqueAttackingIps << ","
        << "\"unique_usernames_targeted\":" << report.uniqueUsernamesTargeted
        << "}\n";
}

void printRankedHuman(
    const std::vector<std::pair<std::string, std::size_t>>& ranked,
    const std::string& label
) {
    if (ranked.empty()) {
        std::cout << "No data found.\n";
        return;
    }

    for (const auto& item : ranked) {
        std::cout << std::left << std::setw(18) << item.first << " " << item.second << " " << label << "\n";
    }
}

void printRankedJson(const std::vector<std::pair<std::string, std::size_t>>& ranked, const std::string& keyName) {
    printJsonArray<std::pair<std::string, std::size_t>>(
        ranked,
        [&keyName](const std::pair<std::string, std::size_t>& row, std::size_t) {
            std::cout << "{"
                      << "\"" << keyName << "\":\"" << jsonEscape(row.first) << "\","
                      << "\"count\":" << row.second
                      << "}";
        }
    );
}

void printAlertsHuman(const std::vector<DetectionAlert>& alerts) {
    if (alerts.empty()) {
        std::cout << "No alerts detected.\n";
        return;
    }

    for (const DetectionAlert& alert : alerts) {
        std::cout << "ALERT: " << toString(alert.type) << "\n";
        std::cout << "IP: " << alert.ipAddress << "\n";
        std::cout << "Failed attempts: " << alert.failedAttempts << "\n";
        std::cout << "Users targeted: " << alert.targetedUserCount << "\n";
        if (!alert.users.empty()) {
            std::cout << "User list: " << join(alert.users, ", ") << "\n";
        }
        std::cout << "Reason: " << alert.description << "\n\n";
    }
}

void printAlertsJson(const std::vector<DetectionAlert>& alerts) {
    printJsonArray<DetectionAlert>(
        alerts,
        [](const DetectionAlert& alert, std::size_t) {
            std::cout
                << "{"
                << "\"type\":\"" << jsonEscape(toString(alert.type)) << "\","
                << "\"ip_address\":\"" << jsonEscape(alert.ipAddress) << "\","
                << "\"failed_attempts\":" << alert.failedAttempts << ","
                << "\"targeted_user_count\":" << alert.targetedUserCount << ","
                << "\"description\":\"" << jsonEscape(alert.description) << "\","
                << "\"users\":[";
            for (std::size_t i = 0; i < alert.users.size(); ++i) {
                std::cout << "\"" << jsonEscape(alert.users[i]) << "\"";
                if (i + 1 < alert.users.size()) {
                    std::cout << ",";
                }
            }
            std::cout << "]"
                      << "}";
        }
    );
}

int runWatchMode(const std::string& logFile, const QueryOptions& options) {
    std::size_t processedLines = 0;
    AuthLogParser parser;

    const std::unordered_set<std::string> allowlist(options.allowlistIps.begin(), options.allowlistIps.end());
    const std::unordered_set<std::string> denylist(options.denylistIps.begin(), options.denylistIps.end());

    std::cout
        << "Watching " << logFile
        << " every " << options.watchIntervalSeconds
        << "s. Press Ctrl+C to stop.\n";

    while (true) {
        std::ifstream file(logFile);
        if (!file.is_open()) {
            std::cerr << "Error: could not open log file: " << logFile << "\n";
            return 1;
        }

        std::vector<LogEvent> newEvents;
        std::string line;
        std::size_t lineNumber = 0;
        while (std::getline(file, line)) {
            ++lineNumber;
            if (lineNumber <= processedLines) {
                continue;
            }
            const std::optional<LogEvent> parsed = parser.parseLine(line, lineNumber);
            if (parsed.has_value()) {
                newEvents.push_back(parsed.value());
            }
        }

        if (lineNumber < processedLines) {
            processedLines = 0;
            continue;
        }
        processedLines = lineNumber;

        if (!newEvents.empty()) {
            QueryOptions scanOptions = options;
            std::vector<LogEvent> filtered = filterEventsByTime(newEvents, scanOptions);
            LogAnalyzer analyzer(std::move(filtered));

            std::cout << "\nNew events: " << analyzer.events().size() << "\n";
            printEventsHuman(analyzer.events());

            std::vector<DetectionAlert> alerts = analyzer.detect(options.detectionConfig, allowlist, denylist);
            if (!alerts.empty()) {
                std::cout << "\nAlerts from new events:\n";
                printAlertsHuman(alerts);
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(options.watchIntervalSeconds));
    }
}

}  // namespace

int runCli(const int argc, char** argv) {
    const ParsedInput parsed = parseArgs(argc, argv);
    if (!parsed.error.empty()) {
        std::cerr << "Error: " << parsed.error << "\n\n";
        if (isCommand(parsed.command)) {
            printCommandHelp(parsed.command);
        } else {
            printGeneralHelp();
        }
        return 1;
    }

    if (parsed.showHelp) {
        printGeneralHelp();
        return 0;
    }

    if (parsed.commandHelp) {
        printCommandHelp(parsed.command);
        return 0;
    }

    if (parsed.command == "watch") {
        return runWatchMode(parsed.logFile, parsed.options);
    }

    AuthLogParser parser;
    ParseStats stats;
    std::vector<LogEvent> events;
    try {
        events = parser.parseFile(parsed.logFile, stats);
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }

    if (stats.totalLines == 0) {
        std::cerr << "Error: log file is empty.\n";
        return 1;
    }

    events = filterEventsByTime(events, parsed.options);
    LogAnalyzer analyzer(events);

    const std::unordered_set<std::string> allowlist(parsed.options.allowlistIps.begin(), parsed.options.allowlistIps.end());
    const std::unordered_set<std::string> denylist(parsed.options.denylistIps.begin(), parsed.options.denylistIps.end());

    if (parsed.command == "failures") {
        std::vector<LogEvent> rows = limitEvents(analyzer.failures(), parsed.options.limit);
        if (parsed.options.json) {
            printEventsJson(rows);
        } else {
            printEventsHuman(rows);
        }
        return 0;
    }

    if (parsed.command == "successes") {
        std::vector<LogEvent> rows = limitEvents(analyzer.successes(), parsed.options.limit);
        if (parsed.options.json) {
            printEventsJson(rows);
        } else {
            printEventsHuman(rows);
        }
        return 0;
    }

    if (parsed.command == "summary") {
        const SummaryReport report = analyzer.summary(stats);
        if (parsed.options.json) {
            printSummaryJson(report);
        } else {
            printSummaryHuman(report);
        }
        return 0;
    }

    if (parsed.command == "top-ips") {
        const std::vector<std::pair<std::string, std::size_t>> ranked =
            analyzer.topFailedIps(parsed.options.limit, &allowlist);
        if (parsed.options.json) {
            printRankedJson(ranked, "ip_address");
        } else {
            printRankedHuman(ranked, "failures");
        }
        return 0;
    }

    if (parsed.command == "top-users") {
        const std::vector<std::pair<std::string, std::size_t>> ranked = analyzer.topUsers(parsed.options.limit);
        if (parsed.options.json) {
            printRankedJson(ranked, "username");
        } else {
            printRankedHuman(ranked, "events");
        }
        return 0;
    }

    if (parsed.command == "detect") {
        std::vector<DetectionAlert> alerts = analyzer.detect(parsed.options.detectionConfig, allowlist, denylist);
        alerts = limitAlerts(std::move(alerts), parsed.options.limit);
        if (parsed.options.json) {
            printAlertsJson(alerts);
        } else {
            printAlertsHuman(alerts);
        }
        return 0;
    }

    if (parsed.command == "report") {
        const SummaryReport report = analyzer.summary(stats);
        const std::vector<std::pair<std::string, std::size_t>> topIps =
            analyzer.topFailedIps(parsed.options.limit, &allowlist);
        std::vector<DetectionAlert> alerts = analyzer.detect(parsed.options.detectionConfig, allowlist, denylist);
        alerts = limitAlerts(std::move(alerts), parsed.options.limit);

        if (parsed.options.json) {
            std::cout << "{";
            std::cout << "\"summary\":{"
                      << "\"total_lines_read\":" << report.totalLinesRead << ","
                      << "\"total_parsed_security_events\":" << report.totalParsedSecurityEvents << ","
                      << "\"failed_login_count\":" << report.failedLoginCount << ","
                      << "\"successful_login_count\":" << report.successfulLoginCount << ","
                      << "\"unique_attacking_ips\":" << report.uniqueAttackingIps << ","
                      << "\"unique_usernames_targeted\":" << report.uniqueUsernamesTargeted
                      << "},";

            std::cout << "\"top_ips\":[";
            for (std::size_t i = 0; i < topIps.size(); ++i) {
                std::cout
                    << "{"
                    << "\"ip_address\":\"" << jsonEscape(topIps[i].first) << "\","
                    << "\"count\":" << topIps[i].second
                    << "}";
                if (i + 1 < topIps.size()) {
                    std::cout << ",";
                }
            }
            std::cout << "],";

            std::cout << "\"alerts\":[";
            for (std::size_t i = 0; i < alerts.size(); ++i) {
                std::cout
                    << "{"
                    << "\"type\":\"" << jsonEscape(toString(alerts[i].type)) << "\","
                    << "\"ip_address\":\"" << jsonEscape(alerts[i].ipAddress) << "\","
                    << "\"failed_attempts\":" << alerts[i].failedAttempts
                    << "}";
                if (i + 1 < alerts.size()) {
                    std::cout << ",";
                }
            }
            std::cout << "]";
            std::cout << "}\n";
        } else {
            printSummaryHuman(report);
            std::cout << "\nTop IPs\n";
            std::cout << "-------\n";
            printRankedHuman(topIps, "failures");
            std::cout << "\nAlerts\n";
            std::cout << "------\n";
            printAlertsHuman(alerts);
        }
        return 0;
    }

    std::cerr << "Error: unsupported command\n";
    return 1;
}

}  // namespace secscan
