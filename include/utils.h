#pragma once

#include <optional>
#include <string>
#include <vector>

#include "types.h"

namespace secscan {

bool isFailureEvent(EventType type);
bool isSuccessEvent(EventType type);
std::string toString(EventType type);
std::string toString(AlertType type);

std::string trim(const std::string& input);
bool startsWith(const std::string& input, const std::string& prefix);
std::vector<std::string> split(const std::string& input, char delimiter);

std::optional<int> parseClockToMinute(const std::string& value);
std::optional<int> parseTimestampMinute(const std::string& hhmmss);
bool inTimeWindow(int minuteOfDay, const std::optional<int>& sinceMinute, const std::optional<int>& untilMinute);

std::vector<LogEvent> filterEventsByTime(const std::vector<LogEvent>& events, const QueryOptions& options);

std::string jsonEscape(const std::string& input);
std::string join(const std::vector<std::string>& values, const std::string& delimiter);

std::vector<std::string> loadIpListFile(const std::string& path);

}  // namespace secscan
