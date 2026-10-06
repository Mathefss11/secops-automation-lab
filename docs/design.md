# Design Reference

Detailed design notes for SecOps Automation Lab: the normalized schema, detection logic, confidence
weights, correlation keys, ATT&CK mapping rules, threat-intelligence and API handling, risk scoring,
playbook policy and incident report format. The [README](../README.md) gives the overview;
[google-secops.md](google-secops.md) covers the Google SecOps / YARA-L mapping.

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

Severity describes the detection itself. It is not the incident risk score, which the [Risk Engine](#risk-engine) calculates from the detection plus its context. `CRITICAL` is defined for detections but no current detection uses it.

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

## MITRE ATT&CK Mapping

[MITRE ATT&CK](https://attack.mitre.org/) is a public knowledge base of adversary behaviors, organized as tactics (the goal) and techniques (how the goal is reached). Mapping a detection to techniques gives analysts a shared vocabulary, links to documented procedures and mitigations, and a way to see which behaviors detection logic covers.

A mapping means "the observed activity matches this documented behavior". It does **not** prove malicious intent, and ATT&CK is **not** a severity scale. Mapping never changes a detection's severity or confidence.

`src/mitre.py` adds a technique **only when specific evidence in the detection supports it**, and each mapping's `reason` cites that evidence. Technique IDs and names were checked against attack.mitre.org on 2026-10-05.

| Detection | Technique | Added when |
|---|---|---|
| Credential attack | **T1110** Brute Force | always (the detection itself is many failed logins across accounts) |
| PowerShell | **T1059.001** Command and Scripting Interpreter: PowerShell | always (the detection is about a PowerShell process) |
| PowerShell | **T1027.010** Obfuscated Files or Information: Command Obfuscation | the command line uses `-EncodedCommand` |
| PowerShell | **T1564.003** Hide Artifacts: Hidden Window | the command line uses `-WindowStyle Hidden` |
| PowerShell | **T1105** Ingress Tool Transfer | the **same PowerShell process** connected to an external IP **and** created a file |
| Payload | **T1105** Ingress Tool Transfer | the `curl`/`wget` URL host is external (not internal, not localhost) |
| Payload | **T1059.004** Command and Scripting Interpreter: Unix Shell | the downloaded file was executed with a Unix shell (`bash`, `sh`, ...) as parent |

Techniques considered and deliberately **not** mapped:

| Technique | Why not |
|---|---|
| T1110.001 Password Guessing / T1110.003 Password Spraying | the telemetry does not show which passwords were tried, so the parent T1110 is used |
| T1078 Valid Accounts | a successful login after failures is suspicious but does not prove adversary use of the account |
| T1566.001 Spearphishing Attachment | there is no email telemetry, only a file written by Outlook |
| T1204.002 User Execution: Malicious File | the document was opened, but nothing shows it was malicious |
| T1222.002 Linux File and Directory Permissions Modification | `chmod +x` on a downloaded file is a normal execution prerequisite here, not evasion of access controls |
| T1071 Application Layer Protocol / T1041 Exfiltration Over C2 Channel | connections are not shown to be command-and-control, and there is no evidence of data transfer |

## Threat Intelligence

Threat-intelligence enrichment looks up a detection's **external IP indicators** (the source of a credential attack, and external destinations contacted by the PowerShell or payload processes) and attaches what a provider knows about them. Internal IPs are never looked up.

Threat intelligence is **context for an analyst, not proof**. A `MALICIOUS` reputation does not prove compromise, and `UNKNOWN` does not mean benign. Enrichment never changes the detection's evidence, severity or confidence.

Two providers share one small interface (`name`, `simulated`, `lookup_ip(ip)`):

- **`MockThreatIntelProvider` (default)**: deterministic, offline, with invented entries for the dataset's addresses. Every result has `simulated: true`, the source `Mock Threat Intelligence (simulated)` and a disclaimer, and the CLI marks each one `[SIMULATED]`. It exists so the whole project runs offline, deterministically and without credentials, for example in tests and interview demos. The simulated attacker IPs are documentation addresses, so no real intelligence about them exists.
- **`AbuseIPDBProvider` (optional)**: queries the real [AbuseIPDB](https://www.abuseipdb.com/) v2 `check` API. AbuseIPDB was chosen because it is purpose-built for IP reputation (the only indicator type here), has one simple documented endpoint, and returns a clear 0–100 `abuseConfidenceScore`.

Reputation values: `MALICIOUS`, `SUSPICIOUS`, `UNKNOWN`, `BENIGN`, and `UNAVAILABLE` (the lookup failed or was refused). For AbuseIPDB, this project treats a score ≥ 75 as `MALICIOUS` and ≥ 25 as `SUSPICIOUS`. Lower scores are `UNKNOWN`, not `BENIGN`, because "few reports" is not "safe". Whitelisted addresses are `BENIGN`. These thresholds are this project's choice, not AbuseIPDB's.

## API Integration

```
Detection
   ↓  indicators_for(): external IPs only
Indicator (IP)
   ↓  CachedThreatIntel: already looked up this run? → return cached result
   ↓  not public (private, loopback, documentation range)? → refused, never sent
Threat Intelligence API   GET https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>&maxAgeInDays=90
   ↓                      header  Key: $ABUSEIPDB_API_KEY, explicit timeout (10 s)
JSON response             {"data": {"abuseConfidenceScore": ..., "totalReports": ..., ...}}
   ↓  validate status → parse JSON → check required fields
Structured enrichment     ThreatIntelResult(indicator, reputation, confidence, tags, source, simulated, details, error)
```

- **API key**: read from the `ABUSEIPDB_API_KEY` environment variable. It is never hardcoded, logged, printed, put in error messages or exported. `.env` is ignored by Git, and `.env.example` shows the variable name only.
- **Errors**: the provider raises `ThreatIntelError` (with `MissingApiKeyError`, `AuthenticationError` and `RateLimitError` subtypes) for a missing key, HTTP 401/403, HTTP 429 (reports `Retry-After`), other non-200 statuses, timeouts, connection failures, invalid JSON and missing or invalid `abuseConfidenceScore`. Missing optional fields are recorded as `null`.
- **Failures never break the pipeline**: `CachedThreatIntel` converts any `ThreatIntelError` into an `UNAVAILABLE` result with the reason, and detections and ATT&CK mappings are produced regardless.
- **Offline by default**: `python main.py` uses the mock provider and makes no network requests. The real API is used only with `--threat-intel abuseipdb`. If the key is missing, the CLI says AbuseIPDB was **not** queried and does not fall back to mock data.
- **Caching**: a small in-memory dictionary per run. Each IP reaches the provider at most once, and failures are cached too, so a rate-limited API is not called again. Nothing is persisted.
- **Safety**: only the IP address is sent, and only to AbuseIPDB's documented API. The tool never connects to the indicator itself, downloads files, uploads telemetry or scans anything. Non-public addresses are refused before any request.

Because the simulated attacker IPs are RFC 5737 documentation addresses, running the real provider against the bundled dataset reports them as *not publicly routable / not sent*. That is the correct behavior. Use `--lookup-ip` to try the real API on a real public address.

## Risk Engine

Detection confidence and incident risk answer different questions:

| | Question | Example |
|---|---|---|
| **Detection confidence** | *How sure are we that this behavior matches the detection?* | 0.95: almost every expected signal of a payload download-and-execute chain is present |
| **Incident risk** | *How serious is the resulting incident, given the evidence and its context?* | 98/100: the payload ran, connected out, and the same account was just taken over by a credential attack |

`src/risk_engine.py` computes a **deterministic 0–100 score** (no ML, no randomness) from four capped categories. Every point comes from a listed contributor with a reason:

| Category | Max | Points |
|---|---|---|
| `detection_evidence` | 40 | detection confidence × 40 |
| `observed_outcome` | 35 | the furthest attack stage the evidence shows: account access **15**, script execution **15**, or payload/file execution **25** (only the highest counts), plus **10** for an outbound external connection by the executed code |
| `related_activity` | 15 | another detection on the **same host and same user** within 60 minutes (referenced, not merged) |
| `threat_intel` | 10 | best reputation among the incident's indicators: MALICIOUS 10, SUSPICIOUS 5, anything else 0 |

**Risk levels:** `0–39 LOW`, `40–59 MEDIUM`, `60–79 HIGH`, `80–100 CRITICAL`.

**No double counting.** Launch-context signals (Office parent, encoded command, hidden window, `chmod`, temp path) already shape the detection confidence, so they are counted **only** through `detection_evidence`. Outcome facts are counted once as impact, however many signals support them, and execution stages do not stack.

**Threat intelligence is context, not authority:**

- It is worth at most 10 of 100 points, and several malicious indicators still count once.
- `UNKNOWN`, `BENIGN` and failed lookups add 0 points. They never subtract, because absence of intelligence is not evidence of safety.
- **Policy:** threat intelligence can never be the only reason an incident reaches CRITICAL. If the score without it is below 80, the level is capped at HIGH and the incident explains why.

Results for the bundled dataset (score without threat intelligence in brackets):

| Incident | Evidence | Outcome | Related | Threat intel | Score | Level |
|---|---|---|---|---|---|---|
| Possible Payload Execution on Linux Host | 38 | 25 + 10 | 15 | 10 (simulated) | **98** (88) | CRITICAL |
| Possible Endpoint Compromise via Suspicious PowerShell | 38 | 25 + 10 | 0 | 5 (simulated) | **78** (73) | HIGH |
| Possible Credential Compromise | 36 | 15 | 15 | 10 (simulated) | **76** (66) | HIGH |

## SOAR-style Automation

```
Detection → Context (ATT&CK + threat intel) → Risk → Decision (playbook policy) → Simulated response
```

`src/playbook.py` turns each incident into deterministic actions using an explicit per-level policy:

| Risk level | Actions |
|---|---|
| LOW | `RECORD_INCIDENT` |
| MEDIUM | record + `ESCALATE_TO_ANALYST` |
| HIGH | record + escalate + `RECOMMEND_*` containment (needs analyst approval) |
| CRITICAL | record + escalate + `SIMULATE_*` containment, **only if detection confidence ≥ 0.80**, otherwise `RECOMMEND_*` |

Containment is chosen per detection type and per affected entity:

| Detection | Containment targets |
|---|---|
| Credential attack | `ACCOUNT_DISABLE` for the user (only if known), `IP_BLOCK` for the source IP (only if external) |
| Suspicious PowerShell | `ENDPOINT_ISOLATION` for the host (only if known), `IP_BLOCK` for external destinations |
| Payload execution | `ENDPOINT_ISOLATION` for the host (only if known), `IP_BLOCK` for external destinations |

Internal IPs are never proposed for blocking. The confidence requirement for automation limits the damage a false positive could do: a high score built on a weaker detection still only produces recommendations.

**All actions are simulated.** `PlaybookAction.simulated` is always `True` and cannot be set otherwise. Every action is printed as `[SIMULATED ACTION]`. The risk, incident and playbook modules import nothing that could run commands, open network connections or change the operating system, and a test checks this statically. Nothing is blocked, disabled, isolated or stopped.

## Incident Reports

Each detection becomes one `Incident` (`src/incident.py`). It wraps the enriched detection (composition, not a copy) and adds the risk assessment and the playbook actions. Related detections are referenced by ID but not merged.

- **Incident ID:** `INC-` + the first 10 hex characters of SHA-256(detection ID), so it is deterministic and reproducible.
- **`created_at`:** simulation time, meaning the timestamp of the incident's last evidence event. This keeps reports reproducible.

`python main.py --export` writes one JSON report per incident to `output/incidents/<incident_id>.json`, in addition to `normalized_events.json` and `detections.json`. File names are the unique incident IDs, so reports never overwrite each other. Each report contains:

- `risk`: score, level, `score_without_threat_intel`, an optional `level_note` and every contributor
- `detection`: ID, name, severity, confidence, host, user, source IP, timestamps, reasoning, signals, evidence, false positives
- `mitre_attack`, `threat_intel` (with `simulated` flags) and `related_detections`
- `recommendations` (actions that need approval) and `playbook_actions` (all actions)
- `simulated_response: true` and a disclaimer
