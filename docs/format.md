# Log Format Decision (v1)

## Supported Log Family

- Debian/Ubuntu style auth logs (`/var/log/auth.log`)
- RHEL/CentOS style secure logs (`/var/log/secure`)
- Requirement: lines must be syslog-like and include `sshd[...]` plus one of the supported SSH messages

## Supported Event Patterns

SecScan v1 parses these SSH messages:

1. `Failed password for <user> from <ip> port <port> ssh2`
2. `Failed password for invalid user <user> from <ip> port <port> ssh2`
3. `Accepted password for <user> from <ip> port <port> ssh2`
4. `Accepted publickey for <user> from <ip> port <port> ssh2`

## Expected Prefix Shape

```text
<Mon> <Day> <HH:MM:SS> <host> sshd[pid]: <event message>
```

Example:

```text
Mar  9 10:22:01 server sshd[1234]: Failed password for root from 10.0.0.4 port 22 ssh2
```

## Parsed Fields

- `raw_line`
- `timestamp_text`
- `hostname`
- `process`
- `event_type`
- `username`
- `ip_address`
- `port`
- `line_number`
- `minute_of_day`

## Explicitly Ignored in v1

- Non-`sshd` lines (`sudo`, `pam`, kernel, cron, etc.)
- SSH lines that are not in the supported patterns (for example `session opened`, disconnect-only lines)
- Non-syslog formatted lines
