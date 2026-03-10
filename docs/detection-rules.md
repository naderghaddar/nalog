# Detection Rules

SecScan v1 uses simple explainable detection logic.

## 1) Brute-Force Candidate

Condition:

- one IP has failed attempts greater than `bruteforce-threshold`

Default threshold:

- `20`

CLI override:

```bash
secscan detect auth.log --bruteforce-threshold 10
```

## 2) Username Spray Candidate

Condition:

- one IP fails against many distinct usernames
- distinct username count is greater than or equal to `spray-threshold`

Default threshold:

- `5`

CLI override:

```bash
secscan detect auth.log --spray-threshold 6
```

## 3) Suspicious Success Candidate

Condition:

- same IP accumulates many failed attempts
- then succeeds later from the same IP
- failure count before success is greater than or equal to `suspicious-failure-threshold`

Default threshold:

- `5`

CLI override:

```bash
secscan detect auth.log --suspicious-failure-threshold 8
```

## 4) Denylisted Activity

Condition:

- an observed IP appears in the provided denylist file

CLI usage:

```bash
secscan detect auth.log --denylist examples/denylist.txt
```

## Allowlist Behavior

If `--allowlist` is supplied, listed IPs are ignored by threshold-based detections and by `top-ips`.
