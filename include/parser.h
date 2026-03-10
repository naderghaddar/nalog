#pragma once

#include <optional>
#include <string>
#include <vector>

#include "types.h"

namespace secscan {

class AuthLogParser {
public:
    std::optional<LogEvent> parseLine(const std::string& rawLine, std::size_t lineNumber) const;
    std::vector<LogEvent> parseFile(const std::string& path, ParseStats& stats) const;
};

}  // namespace secscan
