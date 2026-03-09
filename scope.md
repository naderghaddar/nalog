PROJECT: Linux Security Log Analyzer in C++
Goal: build a real CLI tool that parses Linux auth/security logs, detects suspicious login activity, and can grow into a serious open-source utility.

======================================================================
PHASE 0 — DEFINE THE PROJECT PROPERLY
======================================================================

Main objective:
Build a command-line C++ program that analyzes Linux authentication logs,
starting with SSH-related login events.

What version 1 should do:
- read a Linux auth log file
- detect failed SSH login attempts
- detect successful SSH logins
- extract usernames and IP addresses
- count and summarize suspicious activity
- provide useful CLI commands

What NOT to do in version 1:
- no GUI
- no web dashboard
- no cloud integration
- no machine learning
- no support for every Linux log format
- no real-time monitoring at first
- no multithreading at first

Initial target log family:
- Linux SSH/authentication logs
  Examples:
- /var/log/auth.log on Debian/Ubuntu
- /var/log/secure on some RHEL/CentOS systems

Broad deliverable for v1:
A CLI tool someone can build locally and run on a sample or real auth log.

----------------------------------------------------------------------
Substeps
----------------------------------------------------------------------

1. Pick a project name
   Examples:
    - secscan
    - authscope
    - sshield
    - logsentinel

2. Write a one-line project description
   Example:
   "A C++ CLI tool for analyzing Linux authentication logs and detecting suspicious SSH activity."

3. Define the exact first use case
   Example:
   "Given an auth log, identify failed login attempts, successful logins, top attacking IPs, and possible brute-force behavior."

4. Create a small scope contract for yourself
   Example:
   "I will only support SSH auth log lines first. Anything else is future work."

======================================================================
PHASE 1 — SET UP THE REPOSITORY LIKE A REAL PROJECT
======================================================================

Main objective:
Create a clean project structure from day 1 so the repo already looks serious.

Recommended structure:

project-root/
README.md
LICENSE
.gitignore
CMakeLists.txt
docs/
examples/
include/
src/
tests/

----------------------------------------------------------------------
Substeps
----------------------------------------------------------------------

1. Initialize Git repo

2. Add base files
    - README.md
    - LICENSE
    - .gitignore
    - CMakeLists.txt

3. Create directories
    - src/
    - include/
    - examples/
    - tests/
    - docs/

4. Decide your coding structure early
   Suggested source layout:
    - src/main.cpp
    - src/cli.cpp
    - src/parser.cpp
    - src/analyzer.cpp
    - src/utils.cpp

   Suggested headers:
    - include/cli.h
    - include/parser.h
    - include/analyzer.h
    - include/types.h
    - include/utils.h

5. Make a minimal build work
   Goal:
    - cmake config works
    - project compiles
    - running binary prints "hello" or usage info

6. Write an initial README with:
    - project purpose
    - current status
    - how to build
    - roadmap

Deliverable for this phase:
A compilable empty CLI project with professional structure.

======================================================================
PHASE 2 — UNDERSTAND AND FREEZE THE FIRST LOG FORMAT
======================================================================

Main objective:
Choose exactly what kind of log lines you support first.

Target first:
Common SSH auth log lines such as:

- Failed password for invalid user admin from 10.0.0.4 port 22 ssh2
- Failed password for root from 10.0.0.4 port 22 ssh2
- Accepted password for nader from 192.168.1.5 port 53422 ssh2
- Accepted publickey for user from 1.2.3.4 port 3333 ssh2

With full syslog-style prefix, for example:
Mar  9 10:22:01 server sshd[1234]: Failed password for root from 10.0.0.4 port 22 ssh2

----------------------------------------------------------------------
Substeps
----------------------------------------------------------------------

1. Collect sample logs
    - create examples/auth_sample.log
    - include 30–100 realistic lines
    - include both normal and suspicious behavior

2. Study the line structure
   Identify components:
    - month/day/time
    - host
    - service/process
    - event message
    - username
    - IP
    - port

3. Define which events matter in v1
   Start with:
    - failed password
    - accepted password
    - accepted publickey

4. Ignore everything else for now
   Example:
    - session opened
    - pam messages
    - sudo entries
    - system boot messages

5. Create a simple event model
   Example fields for your internal struct:
    - raw_line
    - timestamp
    - hostname
    - process
    - event_type
    - username
    - ip_address
    - port
    - valid

6. Write this format decision in docs/format.md

Deliverable for this phase:
You know exactly what input your parser is designed for.

======================================================================
PHASE 3 — BUILD THE SIMPLEST POSSIBLE WORKING PARSER
======================================================================

Main objective:
Read a log file line by line and identify failed SSH login attempts.

----------------------------------------------------------------------
Substeps
----------------------------------------------------------------------

1. Implement file reading
   Goal:
    - accept a file path from the command line
    - open file
    - read line by line

2. Add a first command
   Example:
   secscan failures auth.log

3. Detect lines containing failed login attempts
   Start simple:
    - substring matching for "Failed password"

4. Print matching lines only

5. Test on your sample log

6. Handle basic errors
    - file not found
    - empty file
    - bad arguments

7. Add usage help
   Example:
   secscan <command> <logfile>

Deliverable for this phase:
A working tool that can extract failed login lines from a log file.

======================================================================
PHASE 4 — PARSE USEFUL FIELDS OUT OF THE LOG LINE
======================================================================

Main objective:
Turn raw log lines into structured records.

----------------------------------------------------------------------
Substeps
----------------------------------------------------------------------

1. Create an internal LogEvent struct
   Suggested fields:
    - raw_line
    - event_type
    - username
    - ip_address
    - port
    - timestamp_text

2. Implement parsing for failed login lines
   Extract:
    - event_type = FAILED_PASSWORD
    - username
    - ip_address
    - port

3. Implement parsing for successful login lines
   Extract:
    - event_type = ACCEPTED_PASSWORD or ACCEPTED_PUBLICKEY
    - username
    - ip_address
    - port

4. Decide how to parse
   Recommended order:
    - first use simple string operations
    - only introduce regex later if truly needed

5. Add a parser function
   Example:
   parse_line(raw_line) -> optional LogEvent

6. Ignore lines that do not match supported patterns

7. Print parsed events in a clear format for debugging
   Example:
   [FAILED_PASSWORD] user=root ip=10.0.0.4 port=22

Deliverable for this phase:
Your tool no longer just greps lines; it understands key fields.

======================================================================
PHASE 5 — ADD BASIC ANALYSIS COMMANDS
======================================================================

Main objective:
Make the tool useful, not just technically functional.

Core commands for v1:

- failures
- successes
- summary
- top-ips
- top-users

----------------------------------------------------------------------
Substeps
----------------------------------------------------------------------

1. failures command
   Purpose:
    - list parsed failed login events

2. successes command
   Purpose:
    - list parsed accepted login events

3. summary command
   Purpose:
    - print useful totals
      Suggested output:
    - total lines read
    - total parsed security events
    - failed login count
    - successful login count
    - unique attacking IPs
    - unique usernames targeted

4. top-ips command
   Purpose:
    - count failed attempts per IP
      Implementation:
    - use unordered_map<string, int>

5. top-users command
   Purpose:
    - count how often each username was targeted or successfully used

6. Sort outputs
   Example:
    - show top IPs descending by failed attempts

7. Make output clean and readable
   Example:
   10.0.0.4        53 failures
   192.168.1.8     12 failures

Deliverable for this phase:
A genuinely useful CLI log analyzer.

======================================================================
PHASE 6 — ADD FIRST SECURITY DETECTION FEATURES
======================================================================

Main objective:
Go beyond counting and actually detect suspicious behavior.

Version 1 security logic should stay simple and explainable.

----------------------------------------------------------------------
Substeps
----------------------------------------------------------------------

1. Define simple detection rules
   Example rules:
    - brute force candidate: one IP has more than N failed attempts
    - username spray candidate: one IP targets many usernames
    - risky success candidate: many failures followed by one success from same IP

2. Add a detect command
   Example:
   secscan detect auth.log

3. Implement brute-force detection
   Logic:
    - count failures per IP
    - if failures > threshold, flag it

4. Implement username-spray detection
   Logic:
    - one IP fails against many distinct usernames

5. Implement suspicious-success detection
   Logic:
    - same IP has many failures then a success later

6. Print explainable alerts
   Example:
   ALERT: possible brute-force attack
   IP: 10.0.0.4
   Failed attempts: 53
   Users targeted: root, admin, ubuntu

7. Keep thresholds configurable later
   For now hardcode if needed, but design so config can be added

Deliverable for this phase:
The project now has real security value, not just parsing.

======================================================================
PHASE 7 — CLEAN UP THE CLI AND USER EXPERIENCE
======================================================================

Main objective:
Make it feel like a tool, not a coding exercise.

----------------------------------------------------------------------
Substeps
----------------------------------------------------------------------

1. Standardize commands
   Example:
   secscan failures <file>
   secscan successes <file>
   secscan summary <file>
   secscan top-ips <file>
   secscan top-users <file>
   secscan detect <file>

2. Add help output
   Example:
   secscan --help
   secscan summary --help

3. Improve error messages
   Examples:
    - unsupported command
    - missing file path
    - no supported log lines found

4. Add optional flags later
   Examples:
    - --limit 10
    - --json
    - --threshold 20

5. Make output consistent
    - aligned columns
    - stable headers
    - readable alert blocks

6. Separate machine-readable and human-readable output later
   For now focus on human-readable

Deliverable for this phase:
The project feels usable by someone who did not write it.

======================================================================
PHASE 8 — TESTING AND VALIDATION
======================================================================

Main objective:
Make sure the tool is correct and does not break easily.

----------------------------------------------------------------------
Substeps
----------------------------------------------------------------------

1. Create multiple example log files
    - normal activity
    - obvious attack activity
    - mixed activity
    - malformed lines

2. Write parser tests
   Test:
    - failed password line parses correctly
    - accepted password line parses correctly
    - invalid line is rejected safely

3. Write analyzer tests
   Test:
    - IP counts are correct
    - top usernames are correct
    - brute-force detection triggers correctly

4. Test weird edge cases
    - empty file
    - huge file
    - corrupted line
    - unsupported format

5. Decide on a test framework
   Optional:
    - Catch2
    - GoogleTest
      Or start with simple assertions if needed

6. Add expected outputs for sample logs

Deliverable for this phase:
You can trust your parser and analysis logic.

======================================================================
PHASE 9 — DOCUMENTATION THAT MAKES THE REPO LOOK STRONG
======================================================================

Main objective:
Document the project like an open-source utility.

----------------------------------------------------------------------
Substeps
----------------------------------------------------------------------

1. Improve README.md
   Include:
    - what it does
    - why it exists
    - supported logs
    - how to build
    - example commands
    - sample outputs
    - roadmap

2. Add docs/architecture.md
   Explain:
    - CLI layer
    - parser layer
    - analyzer layer
    - future extensibility

3. Add docs/supported-formats.md
   Explain:
    - what log patterns are currently supported
    - what is intentionally unsupported

4. Add docs/detection-rules.md
   Explain:
    - brute-force logic
    - username spray logic
    - suspicious success logic

5. Add docs/roadmap.md
   Future features:
    - watch mode
    - support for more log formats
    - JSON output
    - packaging
    - multithreading

6. Add examples in README
   Example:
   secscan summary examples/auth_sample.log

Deliverable for this phase:
The repo looks much more serious to recruiters and enthusiasts.

======================================================================
PHASE 10 — VERSION 1 RELEASE
======================================================================

Main objective:
Ship a clean first public version.

----------------------------------------------------------------------
Substeps
----------------------------------------------------------------------

1. Freeze scope
   v1 includes:
    - SSH auth log parsing
    - failures/successes/summary/top-ips/top-users/detect
    - clean README
    - build instructions
    - tests for critical parsing logic

2. Tag a release
   Example:
   v1.0.0

3. Add release notes
   Include:
    - supported features
    - known limitations
    - next planned features

4. Make installation simple
   At minimum:
    - clone
    - cmake
    - build
    - run

5. Confirm project works on at least one real log file

Deliverable for this phase:
A complete, public, résumé-worthy version 1.

======================================================================
PHASE 11 — PHASE 2 EXPANSION: MAKE IT MORE REAL
======================================================================

Main objective:
Turn it from a solid student/open-source project into a genuinely practical tool.

----------------------------------------------------------------------
Substeps
----------------------------------------------------------------------

1. Add watch mode
   Example:
   secscan watch /var/log/auth.log
   Purpose:
    - monitor file as it grows
    - print alerts in real time

2. Add threshold configuration
   Example:
   --bruteforce-threshold 15

3. Add JSON output mode
   Purpose:
    - make it scriptable
      Example:
      secscan summary auth.log --json

4. Add time filtering
   Example:
   secscan failures auth.log --since "10:00" --until "11:00"

5. Add support for more SSH-related message variants

6. Add support for more Linux distros' auth log differences

Deliverable for this phase:
A much more useful real-world CLI.

======================================================================
PHASE 12 — PERFORMANCE / SYSTEMS ENGINEERING PHASE
======================================================================

Main objective:
This is where the project starts looking impressive to C++ enthusiasts specifically.

----------------------------------------------------------------------
Substeps
----------------------------------------------------------------------

1. Benchmark the current parser
   Measure:
    - lines per second
    - file size throughput
    - memory use

2. Optimize string parsing
    - reduce unnecessary copies
    - use string_view where appropriate
    - avoid expensive regex if possible

3. Improve data structures
    - more efficient counters
    - preallocation where helpful

4. Add large-file tests
    - generate big synthetic auth logs
    - test performance on 100MB, 1GB, larger

5. Consider memory-mapped files later
   Only if it clearly helps and you understand the tradeoffs

6. Add multithreaded parsing only after single-threaded version is solid
   Possible later architecture:
    - split file into chunks
    - parse in parallel
    - merge statistics

7. Write docs/performance.md
   Include:
    - benchmarks
    - bottlenecks
    - optimization decisions

Deliverable for this phase:
Your repo gains real systems-programming weight.

======================================================================
PHASE 13 — NICHE SECURITY SPECIALIZATION
======================================================================

Main objective:
Move from generic Linux auth analysis into narrower security use cases.

Possible directions:
- SSH brute-force specialist tool
- server hardening companion tool
- incident triage utility
- suspicious access correlation engine

----------------------------------------------------------------------
Substeps
----------------------------------------------------------------------

1. Pick one specialization
   Best early niche:
   "SSH attack detection and triage"

2. Add stronger detectors
   Examples:
    - repeated username spray
    - repeated attacks across time windows
    - suspicious success after long failure chain
    - top persistent attacking IPs

3. Add allowlist/denylist support
   Example:
    - ignore internal IP ranges
    - highlight non-allowlisted IPs

4. Add reporting mode
   Example:
   secscan report auth.log
   Output:
    - concise incident summary
    - top suspicious IPs
    - suspicious successes
    - targeted usernames

5. Add export formats later
    - JSON
    - CSV
    - simple markdown report

Deliverable for this phase:
The project becomes a niche security utility rather than just a parser.

======================================================================
PHASE 14 — GENERALIZE INTO AN ENGINE (LATER, NOT NOW)
======================================================================

Main objective:
Only after the SSH auth analyzer is solid, refactor toward a broader engine.

Future architecture idea:

core/
file_reader
parser_interface
analyzer_engine
output_formatter

parsers/
ssh_auth
nginx_access
syslog_json

detectors/
brute_force
spray_attack
suspicious_success

----------------------------------------------------------------------
Substeps
----------------------------------------------------------------------

1. Separate core logic from SSH-specific logic

2. Define parser interfaces

3. Define analyzer interfaces

4. Add a second parser only after refactor is clean
   Good next option:
    - nginx/apache access logs for web attack patterns

5. Keep SSH support best-in-class while generalizing

Deliverable for this phase:
The project grows from one niche tool into a reusable log analysis framework.

======================================================================
RECOMMENDED MILESTONE ORDER
======================================================================

Milestone 1:
Project compiles and reads a file

Milestone 2:
Can print failed SSH login lines

Milestone 3:
Can parse username/IP/port from failed and successful logins

Milestone 4:
Can generate summaries and top-IP statistics

Milestone 5:
Can detect simple brute-force behavior

Milestone 6:
Has tests, docs, and clean CLI commands

Milestone 7:
Version 1 release on GitHub

Milestone 8:
Watch mode, config, better coverage of auth logs

Milestone 9:
Performance tuning and benchmarking

Milestone 10:
Niche security specialization and broader engine design

======================================================================
WHAT TO LEARN ALONG THE WAY
======================================================================

Core C++ topics:
- strings
- file I/O
- structs/classes
- vectors
- unordered_map
- sorting
- error handling
- references and const correctness
- basic modular design
- CMake basics

Later C++ topics:
- string_view
- move semantics
- testing frameworks
- benchmarking
- multithreading
- memory/performance profiling

Security/domain topics:
- Linux auth logs
- SSH login behavior
- brute-force attack patterns
- username spraying
- basic incident triage logic

======================================================================
WHAT VERSION 1 SUCCESS LOOKS LIKE
======================================================================

You know v1 is done when:

- someone can clone the repo
- build it with CMake
- run it on a sample auth log
- get useful outputs from summary, top-ips, and detect
- understand the project from the README
- trust that it works on normal supported SSH auth logs

That is already enough for:
- GitHub portfolio
- résumé project
- interview discussion
- future expansion into a real tool

======================================================================
ONE-SENTENCE STRATEGY
======================================================================

Start as a narrow SSH auth log analyzer, finish a clean and useful v1,
then expand toward stronger detection, better performance, and eventually
a broader Linux security log analysis engine.