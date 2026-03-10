# SecScan

A C++ CLI tool for analyzing Linux authentication logs and detecting suspicious SSH activity.

## Status

- Version: `v1.0.0`
- Scope: SSH auth log analysis (`/var/log/auth.log`, `/var/log/secure` style lines)
- Supported events:
  - `Failed password`
  - `Accepted password`
  - `Accepted publickey`

## First Use Case

Given an auth log, identify failed login attempts, successful logins, top attacking IPs, and possible brute-force behavior.

## Scope Contract

Version 1 only supports SSH auth log lines. Other log families are future work.

## Repository Layout

```text
.
├── CMakeLists.txt
├── CMakePresets.json
├── docs/
├── examples/
├── include/
├── src/
└── tests/
```

## Build Environment

### Prerequisites

- CMake 3.16+
- C++17 compiler
  - Linux: `g++` or `clang++`
  - macOS: Apple Clang
  - Windows: MSVC (Visual Studio 2022+) or MinGW

### Build (Generic CMake)

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Bootstrap Scripts

- Windows: `powershell -ExecutionPolicy Bypass -File scripts/setup_windows.ps1`
- Linux: `chmod +x scripts/setup_linux.sh && ./scripts/setup_linux.sh`

### Build (Presets)

```bash
cmake --preset default
cmake --build --preset default
ctest --preset default
```

Windows MinGW preset:

```bash
cmake --preset windows-mingw
cmake --build --preset windows-mingw
ctest --preset windows-mingw
```

## Commands

```text
secscan failures <logfile> [options]
secscan successes <logfile> [options]
secscan summary <logfile> [options]
secscan top-ips <logfile> [options]
secscan top-users <logfile> [options]
secscan detect <logfile> [options]
secscan report <logfile> [options]
secscan watch <logfile> [options]
```

### Useful Options

- `--limit N`
- `--json`
- `--since HH:MM`
- `--until HH:MM`
- `--bruteforce-threshold N`
- `--spray-threshold N`
- `--suspicious-failure-threshold N`
- `--allowlist <file>`
- `--denylist <file>`
- `--watch-interval N`

## Quick Start

```bash
./secscan summary examples/auth_sample.log
./secscan top-ips examples/auth_sample.log --limit 5
./secscan detect examples/auth_sample.log --bruteforce-threshold 10
```

## Sample Output

```text
Summary
-------
Total lines read: 48
Total parsed security events: 44
Failed login count: 36
Successful login count: 8
Unique attacking IPs: 5
Unique usernames targeted: 20
```

## Testing

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

## Documentation

- [Environment setup](docs/environment-setup.md)
- [Format decision](docs/format.md)
- [Architecture](docs/architecture.md)
- [Supported formats](docs/supported-formats.md)
- [Detection rules](docs/detection-rules.md)
- [Roadmap](docs/roadmap.md)
- [Performance notes](docs/performance.md)
- [Release notes](docs/release-notes-v1.0.0.md)

## License

MIT License. See [LICENSE](LICENSE).
