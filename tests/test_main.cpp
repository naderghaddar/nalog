#include <iostream>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include "analyzer.h"
#include "parser.h"
#include "types.h"
#include "utils.h"

namespace {

struct TestState {
    int total{0};
    int failed{0};
};

void check(TestState& state, const bool condition, const std::string& message) {
    ++state.total;
    if (!condition) {
        ++state.failed;
        std::cerr << "FAIL: " << message << "\n";
    }
}

void parserTests(TestState& state) {
    secscan::AuthLogParser parser;

    {
        const auto event = parser.parseLine(
            "Mar  9 10:22:01 server sshd[1234]: Failed password for root from 10.0.0.4 port 22 ssh2",
            1
        );
        check(state, event.has_value(), "failed password line should parse");
        check(state, event->eventType == secscan::EventType::FailedPassword, "event type should be failed");
        check(state, event->username == "root", "failed username should be root");
        check(state, event->ipAddress == "10.0.0.4", "failed ip should match");
        check(state, event->port == 22, "failed port should be 22");
    }

    {
        const auto event = parser.parseLine(
            "Mar  9 10:22:02 server sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 45522 ssh2",
            2
        );
        check(state, event.has_value(), "invalid user line should parse");
        check(state, event->username == "admin", "invalid user should normalize to username only");
    }

    {
        const auto event = parser.parseLine(
            "Mar  9 10:22:03 server sshd[1234]: Accepted password for nader from 192.168.1.5 port 53422 ssh2",
            3
        );
        check(state, event.has_value(), "accepted password line should parse");
        check(state, event->eventType == secscan::EventType::AcceptedPassword, "accepted password type");
        check(state, event->username == "nader", "accepted username should match");
    }

    {
        const auto event = parser.parseLine(
            "Mar  9 10:22:04 server sshd[1234]: Accepted publickey for ubuntu from 203.0.113.8 port 60001 ssh2",
            4
        );
        check(state, event.has_value(), "accepted publickey line should parse");
        check(state, event->eventType == secscan::EventType::AcceptedPublicKey, "accepted publickey type");
        check(state, event->username == "ubuntu", "publickey username should match");
    }

    {
        const auto event = parser.parseLine(
            "Mar  9 10:22:05 server sudo: pam_unix(sudo:session): session opened",
            5
        );
        check(state, !event.has_value(), "non-sshd line should be ignored");
    }
}

void analyzerTests(TestState& state) {
    secscan::AuthLogParser parser;
    std::vector<secscan::LogEvent> events;

    const std::vector<std::string> lines = {
        "Mar  9 10:00:01 server sshd[1001]: Failed password for root from 10.0.0.4 port 50001 ssh2",
        "Mar  9 10:00:03 server sshd[1002]: Failed password for admin from 10.0.0.4 port 50002 ssh2",
        "Mar  9 10:00:05 server sshd[1003]: Failed password for ubuntu from 10.0.0.4 port 50003 ssh2",
        "Mar  9 10:00:07 server sshd[1004]: Accepted password for root from 10.0.0.4 port 50004 ssh2",
        "Mar  9 10:00:09 server sshd[1005]: Failed password for user from 203.0.113.9 port 50100 ssh2"
    };

    std::size_t lineNo = 1;
    for (const std::string& line : lines) {
        const auto event = parser.parseLine(line, lineNo++);
        if (event.has_value()) {
            events.push_back(event.value());
        }
    }

    secscan::LogAnalyzer analyzer(events);
    const auto failures = analyzer.failures();
    const auto successes = analyzer.successes();
    check(state, failures.size() == 4, "should count 4 failures");
    check(state, successes.size() == 1, "should count 1 success");

    const auto topIps = analyzer.topFailedIps(0);
    check(state, !topIps.empty(), "top ip list should not be empty");
    check(state, topIps.front().first == "10.0.0.4", "top ip should be 10.0.0.4");
    check(state, topIps.front().second == 3, "top ip should have 3 failed attempts");

    const secscan::DetectionConfig cfg{
        2,  // brute force threshold
        3,  // spray threshold
        2   // suspicious success threshold
    };
    const std::unordered_set<std::string> allowlist;
    const std::unordered_set<std::string> denylist = {"203.0.113.9"};

    const auto alerts = analyzer.detect(cfg, allowlist, denylist);
    bool sawBruteForce = false;
    bool sawSpray = false;
    bool sawSuspicious = false;
    bool sawDenylist = false;
    for (const auto& alert : alerts) {
        if (alert.type == secscan::AlertType::BruteForce && alert.ipAddress == "10.0.0.4") {
            sawBruteForce = true;
        }
        if (alert.type == secscan::AlertType::UsernameSpray && alert.ipAddress == "10.0.0.4") {
            sawSpray = true;
        }
        if (alert.type == secscan::AlertType::SuspiciousSuccess && alert.ipAddress == "10.0.0.4") {
            sawSuspicious = true;
        }
        if (alert.type == secscan::AlertType::DenylistedActivity && alert.ipAddress == "203.0.113.9") {
            sawDenylist = true;
        }
    }

    check(state, sawBruteForce, "brute-force alert should trigger");
    check(state, sawSpray, "spray alert should trigger");
    check(state, sawSuspicious, "suspicious success alert should trigger");
    check(state, sawDenylist, "denylist alert should trigger");
}

void timeFilterTests(TestState& state) {
    secscan::AuthLogParser parser;
    std::vector<secscan::LogEvent> events;

    const std::vector<std::string> lines = {
        "Mar  9 09:59:59 server sshd[1001]: Failed password for root from 10.0.0.4 port 50001 ssh2",
        "Mar  9 10:10:00 server sshd[1002]: Failed password for admin from 10.0.0.4 port 50002 ssh2",
        "Mar  9 11:00:00 server sshd[1003]: Accepted password for root from 10.0.0.4 port 50003 ssh2"
    };

    std::size_t lineNo = 1;
    for (const std::string& line : lines) {
        const auto event = parser.parseLine(line, lineNo++);
        if (event.has_value()) {
            events.push_back(event.value());
        }
    }

    secscan::QueryOptions options;
    options.sinceMinute = secscan::parseClockToMinute("10:00");
    options.untilMinute = secscan::parseClockToMinute("10:59");

    const auto filtered = secscan::filterEventsByTime(events, options);
    check(state, filtered.size() == 1, "time filter should keep only 10:xx event");
    check(state, filtered.front().username == "admin", "time-filtered event should be admin failure");
}

}  // namespace

int main() {
    TestState state;
    parserTests(state);
    analyzerTests(state);
    timeFilterTests(state);

    std::cout << "Tests run: " << state.total << "\n";
    if (state.failed > 0) {
        std::cout << "Tests failed: " << state.failed << "\n";
        return 1;
    }

    std::cout << "All tests passed.\n";
    return 0;
}
