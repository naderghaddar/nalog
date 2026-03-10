# Architecture

## Layered Design

SecScan is intentionally split into three core layers:

1. CLI layer (`src/cli.cpp`)
2. Parser layer (`src/parser.cpp`)
3. Analyzer layer (`src/analyzer.cpp`)

This keeps security logic separate from argument handling and output formatting.

## CLI Layer

Responsibilities:

- command parsing and validation
- option parsing (`--limit`, `--json`, thresholds, time filters, allow/deny lists)
- per-command output formatting (human and JSON)
- watch loop (`watch` command)

It does not parse raw log content directly.

## Parser Layer

Responsibilities:

- read auth log file line by line
- parse only supported SSH auth patterns
- extract structured fields into `LogEvent`
- reject unsupported/malformed lines safely

Parser output is a vector of `LogEvent` plus parse statistics.

## Analyzer Layer

Responsibilities:

- event classification (`failures`, `successes`)
- summary statistics
- top-IP and top-user counts
- detection rule execution:
  - brute-force candidate
  - username spray candidate
  - suspicious success candidate
  - denylisted activity

## Data Model

Defined in `include/types.h`:

- `LogEvent`
- `ParseStats`
- `SummaryReport`
- `DetectionConfig`
- `DetectionAlert`
- `QueryOptions`

## Extensibility Direction

The code is structured so it can evolve into a pluggable engine:

- parser interfaces for multiple log families
- detector interfaces for rule packs
- output formatters for human/JSON/CSV/Markdown
