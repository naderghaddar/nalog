# Supported Formats

## Current Support (v1)

SecScan v1 focuses only on SSH authentication activity in Linux auth logs.

Supported message patterns:

- `Failed password for <user> from <ip> port <port> ssh2`
- `Failed password for invalid user <user> from <ip> port <port> ssh2`
- `Accepted password for <user> from <ip> port <port> ssh2`
- `Accepted publickey for <user> from <ip> port <port> ssh2`

Supported prefix shape:

```text
Mon Day HH:MM:SS host sshd[pid]: <message>
```

## Intentionally Unsupported in v1

- sudo/pam/cron/kernel auth-adjacent events
- non-SSH auth entries
- systemd journal JSON output
- SSH messages outside the four patterns above
- non-syslog or heavily customized formats

## Planned Expansion

- additional SSH variants seen in the wild
- distro-specific auth quirks
- optional parser modules for other log families
