# SecOps Automation Lab

## Overview

SecOps Automation Lab is a small, fully local, educational **Detection Engineering / Security Automation** lab written in Python.

It is built in phases. **Phase 1** (this version) covers the foundation: simulated security telemetry, event normalization and a CLI timeline. There is no web UI, database, cloud service or external API.

## Goals

The lab is meant to demonstrate, step by step:

- **Security telemetry**: realistic Linux, Windows and network events, both benign and suspicious
- **Normalization**: mapping vendor-specific logs onto one common schema
- **Detection engineering**: writing detection logic against normalized events
- **Security automation**: enrichment, risk scoring and SOAR-style response

Only telemetry and normalization exist right now. Later phases will add detection, enrichment and automation on top of the normalized events.

## Current Architecture

```
Simulated Telemetry   (data/security_events.json)
        ↓
Normalizer            (src/normalizer.py)
        ↓
Normalized Events
        ↓
CLI Timeline          (main.py)
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

No single event here proves malicious activity. A failed login, a PowerShell process or a `curl` command means nothing on its own. Telling suspicious activity apart from noise takes context and correlation, which later phases will add.

All IPs and domains for the external actor come from documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, RFC 5737) and the reserved `.example` TLD (RFC 2606).

## Running Locally

Requires Python 3.10+.

```bash
cd secops-automation-lab

# optional: create a virtual environment
python -m venv .venv
# Windows:      .venv\Scripts\activate
# Linux/macOS:  source .venv/bin/activate

pip install -r requirements.txt

# print the normalized timeline
python main.py

# show one normalized event in full (IDs are printed in the timeline)
python main.py --inspect 0910fc527510

# also write all normalized events to output/normalized_events.json
python main.py --export
```

The CLI itself only uses the standard library. `pytest` is only needed for tests.

## Tests

```bash
python -m pytest -v
```

The tests cover each event type, raw-event preservation, missing or placeholder fields, rejection of unsupported events, the same concept arriving in different vendor formats, and full normalization of the bundled dataset.

## Disclaimer

- All telemetry is **simulated**. It does not come from real systems, users or incidents.
- This is an **educational lab, not a production SIEM**.
- The normalized schema is a small internal model. It takes inspiration from concepts such as principal/target, but it **is not Google SecOps UDM** and makes no claim of UDM compatibility.
- The project runs locally, calls no external services and **does not modify any real infrastructure**.
