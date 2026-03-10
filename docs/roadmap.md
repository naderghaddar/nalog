# Roadmap

## v1.0.0 (Completed)

- CMake-based C++17 project structure
- parser for core SSH auth patterns
- commands:
  - `failures`
  - `successes`
  - `summary`
  - `top-ips`
  - `top-users`
  - `detect`
  - `report`
  - `watch`
- detection rules:
  - brute-force
  - username spray
  - suspicious success
  - denylisted activity
- sample logs and tests
- documentation set

## v1.x Improvements

- improve SSH variant coverage
- richer command-specific help
- structured JSON schema stabilization
- additional parser/analyzer tests

## v2 Direction

- real-time watch mode hardening (rotation handling, lower overhead)
- threshold config files
- advanced time-window correlation
- report exports (JSON/CSV/Markdown)
- allowlist ranges/CIDR support

## v3 Direction

- parser interface and detector plugin model
- additional log families (web/access/system logs)
- benchmarking suite and performance dashboards
- optional parallel parsing after single-thread optimization
