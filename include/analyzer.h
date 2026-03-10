#pragma once

#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "types.h"

namespace secscan {

class LogAnalyzer {
public:
    explicit LogAnalyzer(std::vector<LogEvent> events);

    const std::vector<LogEvent>& events() const;
    std::vector<LogEvent> failures() const;
    std::vector<LogEvent> successes() const;

    SummaryReport summary(const ParseStats& stats) const;
    std::vector<std::pair<std::string, std::size_t>> topFailedIps(
        std::size_t limit,
        const std::unordered_set<std::string>* allowlist = nullptr
    ) const;
    std::vector<std::pair<std::string, std::size_t>> topUsers(std::size_t limit) const;

    std::vector<DetectionAlert> detect(
        const DetectionConfig& config,
        const std::unordered_set<std::string>& allowlist,
        const std::unordered_set<std::string>& denylist
    ) const;

private:
    std::vector<LogEvent> events_;
};

}  // namespace secscan
