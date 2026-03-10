# Performance Notes

## Current Approach

SecScan v1 uses single-threaded streaming file reads and lightweight string parsing.

Design choices:

- avoid regex for main parse path
- parse fields with simple string operations
- use `unordered_map` for counting operations

## Baseline Measurement Plan

Track:

- lines per second
- throughput MB/s
- peak memory

Test sizes:

- 10 MB
- 100 MB
- 1 GB

## Optimization Backlog

1. reduce temporary string allocations
2. evaluate `string_view` adoption in parse path
3. pre-size hot hash maps using heuristics
4. add synthetic large-log generator for repeatable benchmarks
5. investigate memory-mapped files only if profiling justifies it

## Multithreading Policy

Parallel parsing is intentionally deferred until:

- parser correctness is stable
- bottlenecks are measured
- merge strategy for counters/alerts is designed cleanly
