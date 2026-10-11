# syslog-siem-correlator (`siemcorrelate`)

Universal security log parser, temporal sliding window correlation engine, and SIGMA detection rule processor engineered with 100% pure Python standard library.

## Features

- **Multi-Format Log Parser**: Parses RFC 3164 (BSD syslog), RFC 5424 (IETF syslog with structured data), ArcSight Common Event Format (CEF), and QRadar Log Event Extended Format (LEEF 1.0 & 2.0) into a canonical dictionary.
- **Sliding Temporal Window Correlator**: In-memory $O(1)$ amortized sliding window correlation engine backed by `collections.deque` with automated event expiration.
- **Pure Stdlib SIGMA Detection Rules**: Zero-dependency YAML parser and conditional rule matcher supporting `contains`, `startswith`, `endswith`, `re`, and `cidr` modifiers with boolean condition logic.
- **Historical Log Replayer**: Time-accelerated or instant historical log stream playback with live alert triggering.
- **Dedicated CLI Binary**: Comprehensive `siemcorrelate` command-line utility with standard POSIX exit codes.

## Installation

```bash
pip install -e .
```

## CLI Usage

### 1. Parse Logs
```bash
# Parse with auto-detection
siemcorrelate parse -i /var/log/syslog -o parsed.jsonl

# Parse explicit CEF format
siemcorrelate parse -i security_events.log -f cef
```

### 2. Correlate Events
```bash
# Alert if 5 events from same src_ip arrive within 300 seconds
siemcorrelate correlate -i auth.log --window 300 --threshold 5 --group-by src_ip
```

### 3. SIGMA Detection Rules
```bash
# Validate rule syntax
siemcorrelate rules --validate rules/ssh_bruteforce.yml

# Test rule against an event
siemcorrelate rules --rule rules/ssh_bruteforce.yml --test-event '{"app_name":"sshd","message":"Failed password"}'
```

### 4. Historical Log Replay
```bash
# Replay past logs instantly against correlation rules
siemcorrelate replay -f incident.log -s instant --threshold 3 -g src_ip
```

## Exit Codes

- `0`: Operation succeeded / no threats detected.
- `1`: Threat detected or correlation threshold breached.
- `2`: Invalid CLI arguments or syntax error.
- `3`: Malformed log file or missing input.
- `4`: Invalid SIGMA rule schema or syntax error.

## License

MIT License. Copyright (c) 2026 aipd506.
