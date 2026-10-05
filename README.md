# SecOps Automation Lab

## Overview

SecOps Automation Lab is a small, fully local, educational **Detection Engineering / Security Automation** lab written in Python.

It is built in phases. The current version covers:

- **Phase 1**: simulated security telemetry, event normalization and a CLI timeline
- **Phase 2**: a behavioral detection engine that correlates normalized events into explainable detections

There is no web UI, database, cloud service or external API.

## Goals

The lab is meant to demonstrate, step by step:

- **Security telemetry**: realistic Linux, Windows and network events, both benign and suspicious
- **Normalization**: mapping vendor-specific logs onto one common schema
- **Detection engineering**: writing detection logic against normalized events
- **Security automation**: enrichment, risk scoring and SOAR-style response

Telemetry, normalization and behavioral detection exist now. Later phases will add MITRE ATT&CK mapping, threat-intelligence enrichment, risk scoring and simulated SOAR-style response. None of those are implemented yet.

## Current Architecture

```
Simulated Telemetry   (data/security_events.json)
        ↓
Normalization         (src/normalizer.py)
        ↓
Detection Engine      (src/detection_engine.py, src/command_analysis.py)
        ↓
Detection Evidence    (CLI timeline + detections, main.py)
```

## Why Normalize Security Events?

Each security product logs the same idea differently. A source IP shows up as `src_ip` in a parsed sshd log, `source_address` in a firewall log and `SourceIp` in Sysmon. Timestamps can be ISO 8601 strings, epoch milliseconds or naive UTC strings. Windows writes `-` when a field has no value.

Without normalization, every detection and every investigation query has to be written once per vendor. With it, logic like "a process on any host connected to this IP" can be written once against `destination_ip`.

The normalizer also keeps the **original raw event** on every normalized event, so analysts can still see vendor-specific details (for example the full sshd log message) that the common schema does not include.

### Supported log sources

| `log_source`       | Represents                             | Time format                   | Example vendor fields                  |
|--------------------|----------------------------------------|-------------------------------|----------------------------------------|
| `linux_sshd`       | OpenSSH auth logs (syslog, pre-parsed) | ISO 8601 with offset          | `user`, `src_ip`, `host`               |
| `linux_edr`        | Simulated Linux endpoint sensor        | Epoch milliseconds            | `username`, `exe_path`, `cmdline`      |
| `network_firewall` | Simulated perimeter firewall           | `YYYY-MM-DD HH:MM:SS` (UTC)   | `source_address`, `destination_address`|
| `windows_security` | Windows Security log 4624 / 4625       | ISO 8601 `Z`                  | `TargetUserName`, `IpAddress`          |
| `sysmon`           | Sysmon Event IDs 1, 3, 11, 22          | `YYYY-MM-DD HH:MM:SS.fff` UTC | `Image`, `CommandLine`, `QueryName`    |

Each raw event has a `log_source` label, similar to the ingestion label a SIEM uses to pick a parser.

### Normalized schema

| Field                                  | Notes                                                                 |
|----------------------------------------|-----------------------------------------------------------------------|
| `event_id`                             | Deterministic ID (truncated SHA-256 of the raw event)                 |
| `timestamp`                            | ISO 8601, UTC, millisecond precision, e.g. `2026-09-14T09:41:03.000Z` |
| `event_type`                           | One of the event types below                                          |
| `vendor`, `log_source`                 | Where the event came from                                             |
| `principal`, `target`                  | Initiating entity and acted-upon entity (see below)                   |
| `user`                                 | Account name, domain prefix removed (`CORP\mgarcia` → `mgarcia`)      |
| `host`                                 | Short hostname (`FIN-WS-07.corp.example.com` → `FIN-WS-07`)           |
| `process`, `parent_process`            | Executable paths                                                      |
| `process_id`, `parent_process_id`      | PIDs, used to tie activity to one process instance                    |
| `command_line`                         | Full command line, if available                                       |
| `source_ip`, `destination_ip`          |                                                                       |
| `destination_port`                     | Always an integer                                                     |
| `dns_query`                            | Queried domain name                                                   |
| `file_path`                            | File created or modified                                              |
| `result`                               | `SUCCESS` / `FAILURE` (authentication), `ALLOWED` / `BLOCKED` (firewall) |
| `raw_event`                            | Unmodified copy of the original event                                 |

Fields that an event does not provide are `null`. Empty strings and `-` placeholders become `null` too.

**Event types:** `AUTHENTICATION`, `PROCESS_CREATE`, `NETWORK_CONNECTION`, `DNS_QUERY`, `FILE_CREATE`, `FILE_MODIFICATION`

**Principal and target.** The principal is the entity that started the action and the target is the entity it acted on. Which fields go where depends on the event type:

| Event type           | Principal                           | Target                      |
|----------------------|-------------------------------------|-----------------------------|
| `AUTHENTICATION`     | source IP                           | user account, host          |
| `PROCESS_CREATE`     | user, host, **parent** process      | new process, command line   |
| `NETWORK_CONNECTION` | user, host, process, source IP      | destination IP and port     |
| `DNS_QUERY`          | user, host, process                 | queried hostname            |
| `FILE_CREATE` / `FILE_MODIFICATION` | user, host, process  | file path                   |

The flat fields (`user`, `source_ip`, ...) are kept for simple querying. `principal` and `target` are built from them and make each entity's role explicit.

## Simulated Scenarios

The dataset (`data/security_events.json`, 45 events) covers one simulated day across three hosts:

- **Linux server (`web-prod-01`)**: A burst of failed SSH logins from one external IP against several usernames, followed by a successful login and shell activity on that host. The data does **not** show whether the same password was tried against each account, so it is not labelled "password spraying".
- **Windows workstation (`FIN-WS-07`)**: An Office document received by email, followed by PowerShell activity and further process and network events that are worth investigating.
- **Benign noise**: Normal SSH admin sessions, `systemctl`, `git pull`, a local `curl` health check, `apt-get update`, a mistyped Windows password followed by a successful login, browsing to GitHub, Outlook traffic, routine PowerShell (`Get-Service`) and Windows Update scans.

No single event here proves malicious activity. A failed login, a PowerShell process or a `curl` command means nothing on its own. Telling suspicious activity apart from noise takes context and correlation, which is what the detection engine does.

All IPs and domains for the external actor come from documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, RFC 5737) and the reserved `.example` TLD (RFC 2606).

## Detection Engine

`src/detection_engine.py` runs three behavioral detections over the normalized events. Each one looks for a **sequence** of related events. None of them fires on a single event or on a tool name alone.

| Detection | Fires when | Severity |
|---|---|---|
| **Credential Attack Followed by Successful Authentication** | ≥ 5 failed logins against ≥ 3 distinct accounts from **one source IP** to **one host**, followed within 5 minutes by a successful login from that same IP to that same host | HIGH |
| **Suspicious PowerShell Execution** | PowerShell starts with suspicious launch context (Office parent, `-EncodedCommand`, hidden window), **and** the confidence from that context plus the follow-on activity of *that same process* reaches 0.35 | MEDIUM, or HIGH at confidence ≥ 0.70 |
| **Payload Download and Execution** | `curl`/`wget` writes a file to an absolute path, and that **same file** is later executed on the same host by the same user within 15 minutes | HIGH if `chmod` added execute permission between download and execution, otherwise MEDIUM |

Some deliberate choices:

- The credential detection is **not** called password spraying. The telemetry does not show whether the same password was tried against each account.
- A download alone never produces a payload detection. **Execution telemetry is required.** The evidence labels the `DOWNLOAD`, `PERMISSION`, `EXECUTION` and `NETWORK` steps separately.
- External connections are reported as external connections. They are never labelled command-and-control or exfiltration, because the telemetry does not show that.
- `src/command_analysis.py` parses command lines as **untrusted strings**. It handles PowerShell flags (including abbreviations such as `-e`, `-enc` and `-W Hidden`), `curl -o` / `wget -O` output paths and `chmod` modes. It can also decode `-EncodedCommand` values (Base64 of UTF-16LE) so analysts can read them. Decoded text is **only displayed, never executed**, and invalid input returns `None`.

Thresholds and windows live in one place, `DetectionConfig`:

```python
DetectionConfig(
    auth_window=timedelta(minutes=5), auth_min_failures=5, auth_min_distinct_accounts=3,
    powershell_window=timedelta(minutes=5), powershell_min_confidence=0.35,
    payload_window=timedelta(minutes=15),
)
```

### Confidence

Confidence (0.0–0.95) is a **deterministic sum of documented signal weights**, not machine learning. Every detection lists the signals that contributed and their weights, so the number can always be explained. It is capped at 0.95 because correlated telemetry still does not prove intent.

| Detection | Base | Additional signals |
|---|---|---|
| Credential attack | 0.70 (thresholds met + success) | external source IP +0.10, an account that failed later succeeded +0.10 |
| PowerShell | 0.00 | Office parent +0.25, encoded command +0.20, hidden window +0.10, DNS query +0.10, external connection +0.10, file created +0.05, created file executed +0.10, that file connected externally +0.05 |
| Payload | 0.55 (download + execution of the same file) | file creation observed +0.05, execute permission added +0.20, temp/hidden path +0.05, external connection after execution +0.10 |

Severity describes the detection itself. It is not an overall incident risk score; a later phase will combine detections with more context. `CRITICAL` is defined but no current detection uses it.

## Event Correlation

Individual events rarely carry enough context. Compare:

- `curl ... -o /tmp/.cache-update` on its own is how many install scripts start.
- The same `curl` command, then `chmod +x` on **that path**, then execution of **that path** by the **same user on the same host**, then an outbound connection **from that process**, is a pattern worth investigating.

The detectors correlate on explicit keys:

- **Credential attack**: source IP + target host + time window.
- **PowerShell**: host + process ID + process image + time window. Operating systems reuse PIDs, so a PID is never trusted on its own. A file counts as "executed" only when a child of that PowerShell process runs the exact path PowerShell created.
- **Payload**: host + user + exact file path + ordering (download → chmod → execution → network).

Correlation uses parsed, timezone-aware UTC timestamps. Events are sorted before correlation, so input order does not matter. Activity from another host, another process or outside the window is not counted.

## Detection Evidence

Each normalized event has a deterministic `event_id` (a truncated SHA-256 of the raw event). Detections reference evidence by these IDs and do not copy whole events. Each evidence entry includes a short description of why it matters. A detection's own `detection_id` comes from its name and evidence IDs, so the same data always produces the same detection IDs.

An analyst can pivot from a detection to the full normalized event and its preserved raw event:

```bash
python main.py --inspect <event_id>       # normalized event + raw_event
python main.py --inspect <DET-id>         # full detection as JSON
```

## False Positives

Correlation reduces false positives. It does not eliminate them. Every detection lists likely benign explanations in its output:

- **Credential attack**: users mistyping passwords, services retrying stale credentials, authorized vulnerability scanners, shared NAT/VPN egress addresses.
- **PowerShell**: administrative automation, software deployment and management tools (some legitimately use `-EncodedCommand` and hidden windows), approved Office add-ins or macros.
- **Payload**: install scripts (`curl -o /tmp/install.sh && chmod +x ...`), DevOps/CI automation, legitimate temporary installers.

The bundled dataset includes benign versions of these behaviors: a mistyped Windows password, admin PowerShell, a local `curl` health check, `apt-get update` and `git pull`. The tests check that none of them trigger a detection.

## Running Locally

Requires Python 3.10+.

```bash
cd secops-automation-lab

# optional: create a virtual environment
python -m venv .venv
# Windows:      .venv\Scripts\activate
# Linux/macOS:  source .venv/bin/activate

pip install -r requirements.txt

# timeline + detections
python main.py

# detections only
python main.py --no-timeline

# show one normalized event or detection in full (IDs are printed in the output)
python main.py --inspect 0910fc527510
python main.py --inspect DET-7240d82770

# also write normalized events and detections to output/
python main.py --export
```

The CLI itself only uses the standard library. `pytest` is only needed for tests.

## Tests

```bash
python -m pytest -v
```

- `tests/test_normalizer.py`: each event type, raw-event preservation, missing or placeholder fields, rejection of unsupported events, multiple vendor formats and the bundled dataset.
- `tests/test_detection_engine.py`: positive **and** negative scenarios for every detection. Negative cases include failures without success, success from a different IP or outside the window, too few accounts, admin PowerShell, Word without PowerShell, activity from another host or process, download without execution, mismatched paths and wrong ordering. It also checks that shuffled input gives the same result, that IDs are deterministic, and that the bundled dataset produces exactly three detections and none on benign hosts.
- `tests/test_command_analysis.py`: PowerShell flag parsing, safe decoding of valid and invalid `-EncodedCommand` values (including a check that decoding never runs anything), and curl/wget/chmod parsing.

## Disclaimer

- All telemetry is **simulated**. It does not come from real systems, users or incidents.
- This is an **educational lab, not a production SIEM**.
- The normalized schema is a small internal model. It takes inspiration from concepts such as principal/target, but it **is not Google SecOps UDM** and makes no claim of UDM compatibility.
- Detections are **behavioral heuristics over simulated data**. They can produce false positives and false negatives, and they do not replace analyst review.
- Telemetry is treated as data: command lines are parsed, **never executed**, and no simulated IP or domain is ever contacted.
- The project runs locally, calls no external services and **does not modify any real infrastructure**.
