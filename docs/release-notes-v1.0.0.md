# Release Notes - v1.0.0

## Highlights

- First complete CLI release of SecScan
- SSH auth log parsing for failed and successful login events
- Security-focused commands for summary, top offenders, and explainable detections

## Included Features

- supported events:
  - failed password
  - accepted password
  - accepted publickey
- commands:
  - `failures`
  - `successes`
  - `summary`
  - `top-ips`
  - `top-users`
  - `detect`
  - `report`
  - `watch`
- optional flags:
  - `--json`
  - `--limit`
  - `--since`, `--until`
  - threshold flags
  - `--allowlist`, `--denylist`

## Testing

- parser unit checks (supported and malformed lines)
- analyzer checks (counts and detection behavior)
- time filter checks

## Known Limitations

- v1 supports only a narrow SSH auth pattern set
- no CIDR matching for allow/deny lists
- watch mode currently polls file content and is not rotation-optimized

## Upgrade Path

Next work focuses on broader SSH coverage, stronger watch mode behavior, and configurable policy profiles.
