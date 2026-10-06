# Google SecOps Mapping

This document explains how the SecOps Automation Lab's local Python pipeline relates to Google Security Operations (Google SecOps). It also walks through three YARA-L 2.0 rules that express the same behavioral detections.

> **Status:** No Google SecOps tenant was available. The YARA-L rules were written from current official documentation and official example rules. They have **not** been compiled, verified, deployed or run in Google SecOps, and no alerts or results from Google SecOps exist for them. See [Limitations](#limitations).

## What Google SecOps Is

Google SecOps is Google Cloud's security operations platform. Its SIEM side ingests security telemetry from many sources, normalizes it into one data model (UDM), and lets analysts search it and run detection rules over it. Detection rules are written in YARA-L 2.0. The platform also includes SOAR capabilities (cases, playbooks and response integrations).

In this lab, those ideas are implemented locally and on a small scale in Python, so they can be run, tested and explained without a cloud tenant.

## Unified Data Model (UDM)

Every security product describes the same activity differently. A source IP may arrive as `src_ip`, `source_address` or `SourceIp`. Without normalization, every detection would have to be rewritten for every vendor.

In Google SecOps, raw logs are parsed into UDM:

```
vendor telemetry  →  parser (per log type)  →  UDM event
```

A UDM event has a `metadata` section (for example `metadata.event_type = "USER_LOGIN"` or `"PROCESS_LAUNCH"`) and *nouns* that describe the entities involved: `principal` (the actor that initiated the activity), `target` (the entity acted on), `src`, `intermediary`, `observer` and `about`. Nouns contain fields such as `hostname`, `ip`, `user.userid`, `process.command_line` and `file.full_path`.

This lab's `NormalizedEvent` (`src/normalizer.py`) follows the same idea: one vendor-neutral record per event, `principal`/`target` roles that depend on the event type, and the raw event preserved alongside.

**The lab's schema is NOT UDM.** It is a small educational model with flat fields (`user`, `host`, `source_ip`, `command_line` ...) and six event types. The field names were not renamed to UDM names, and no claim of UDM compatibility is made. The two are analogous designs:

```
Local lab                                   Google SecOps
---------                                   -------------
data/security_events.json (raw)             raw telemetry
        ↓                                           ↓
src/normalizer.py                           parser / ingestion
        ↓                                           ↓
NormalizedEvent                             UDM event
        ↓                                           ↓
src/detection_engine.py (Python)            YARA-L 2.0 rule
```

Where the concepts line up (taken from the official UDM usage guide):

| Concept | Local `NormalizedEvent` | UDM |
|---|---|---|
| Event type | `AUTHENTICATION`, `PROCESS_CREATE`, `NETWORK_CONNECTION`, `DNS_QUERY`, `FILE_CREATE`, `FILE_MODIFICATION` | `USER_LOGIN`, `PROCESS_LAUNCH`, `NETWORK_CONNECTION`, `NETWORK_DNS`, `FILE_CREATION`, `FILE_MODIFICATION` |
| Login outcome | `result` = `SUCCESS` / `FAILURE` | `security_result.action`, for example `ALLOW` / `BLOCK` (some parsers use `FAIL`) |
| Remote login | principal = source IP, target = user and host | `principal` = originating machine, `target.user` = the account logged into |
| Process launch | principal = parent process, target = new process | `principal.process` = parent, `target.process` = launched process |
| File event | target = `file_path` | `target.file.full_path` |
| Network connection | `destination_ip`, `destination_port` | `target.ip`, `target.port` |

## YARA-L 2.0

YARA-L 2.0 is the language Google SecOps uses for detection rules (and, in a related form, for search and dashboards). A rule describes events to look for in UDM data, how to group them, and when to raise a detection. The sections used in this project:

| Section | Purpose in these rules |
|---|---|
| `meta` | Required. Key/value descriptions: author, description, severity, ATT&CK tactic and technique. |
| `events` | Required. Filters on UDM fields per **event variable** (`$failed_login`, `$powershell` ...). **Placeholder variables** (`$hostname`, `$source_ip` ...) join event variables: the same placeholder in two events means "the same value". Every event variable must be joined to the others. |
| `match` | Groups events by placeholder values inside a time window, for example `$source_ip, $target_host over 5m`. This is what makes a multi-event rule. Windows range from 1 minute to 48 hours. Empty (`""`/`0`) values of match placeholders are filtered out implicitly. |
| `outcome` | Optional. Aggregated context for the analyst (`count_distinct`, `array_distinct`, `min`, `max`). Required to be aggregated when `match` is used. |
| `condition` | Required. When the rule fires. `#var` is the number of distinct events (or distinct placeholder values), and `$var` means "at least one". Every event variable must appear here. |

Two details that the rules rely on:

- **Bounded vs unbounded conditions.** `$e` and `#e >= 1` require the event to exist (bounded). `#e >= 0` lets an event be optional (unbounded): when present, its fields are reported in `outcome`. The documentation notes that queries with unbounded conditions get extra latency (about 1 hour) to allow for late-arriving data.
- **`$risk_score`.** If a rule doesn't set this special outcome variable, Google SecOps uses a default (40 for alerting rules). These rules deliberately do **not** set it. Rule-level risk in SecOps is a different concern from this lab's incident risk engine (`src/risk_engine.py`), and the lab's scores are not copied into YARA-L.

## Local Python vs Google SecOps

| Local project | Google SecOps (closest concept) | Not the same because... |
|---|---|---|
| `data/security_events.json` | ingested raw telemetry | static simulated file vs continuous ingestion |
| `src/normalizer.py` | parsers → UDM | 5 hand-written parsers vs managed per-log-type parsers |
| `NormalizedEvent` | UDM event | 21 mostly flat fields vs a large nested schema |
| `src/detection_engine.py` | YARA-L 2.0 rules | Python code run once over a file vs rules run continuously by the platform |
| `Detection` | detection / alert | local dataclass vs platform object |
| `src/mitre.py` | ATT&CK metadata in rules (`tactic`, `technique`) | evidence-conditional mapping in code vs static rule metadata |
| `src/enrichment.py`, `src/threat_intel.py` | investigation and enrichment context | mock or optional AbuseIPDB vs platform-integrated intelligence |
| `src/risk_engine.py` | `$risk_score` / risk analytics | the lab's own incident model, not SecOps risk scoring |
| `src/playbook.py` | SOAR playbooks | simulated decisions only; no integrations |

These are conceptual analogies, not product equivalence.

## Rule Walkthroughs

Severity in each rule's `meta` reflects the **minimum evidence the rule requires**. YARA-L metadata is static, while the Python engine can raise or lower severity depending on how many signals it observes.

### 1. Credential Attack Followed by Successful Authentication

[`detections/credential_attack.yaral`](../detections/credential_attack.yaral)

- **Events:**
  - `$failed_login`: `USER_LOGIN` with `security_result.action = "BLOCK"`.
  - `$successful_login`: `USER_LOGIN` with `security_result.action = "ALLOW"`.
- **Correlation:**
  - `$source_ip` (from `principal.ip`) and `$target_host` (from `target.hostname`) are shared by both events.
  - `$failed_account` (from the failures' `target.user.userid`) is used to count distinct accounts.
  - The failures must have timestamps `<=` the success.
- **Window:** `match: $source_ip, $target_host over 5m`.
- **Condition:** `#failed_login >= 5 and #failed_account >= 3 and $successful_login`, meaning at least 5 failed logins against at least 3 distinct accounts, plus at least one success.
- **Outcome:** failure count, distinct account count, targeted accounts, authenticated account, and first-failure and success times.
- **Not password spraying:** the rule does not call this password spraying. Login events don't show whether one password was tried across accounts. For comparison, Google's own community rules label similar patterns T1110.001 or T1110.003; see the [MITRE note](#mitre-attck-note).
- **Likely false positives:** users mistyping passwords (usually one account, so filtered out by the 3-account minimum), services retrying stale credentials, authorized scanners, and shared NAT/VPN exit IPs.
- **Telemetry assumptions:**
  - The parser sets `principal.ip` (client) and `target.hostname` (the host being logged into).
  - It maps failures and successes to `BLOCK` and `ALLOW`. Official examples use `BLOCK` in some places and `FAIL` in others, so this is parser-dependent.
  - Events without `target.hostname` never match, because empty match values are filtered out.
- **Difference from Python:** Python counts failures in the 5 minutes *before* each success. A YARA-L `over 5m` hop window groups events within 5 minutes of each other, which is similar but not identical.

### 2. Suspicious PowerShell Execution

[`detections/suspicious_powershell.yaral`](../detections/suspicious_powershell.yaral)

- **Events (all three share `$hostname` and `$powershell_process_id`):**
  - `$powershell`: a `PROCESS_LAUNCH` where the parent (`principal.process.file.full_path`) is an Office application and the new process (`target.process.file.full_path`) is `powershell.exe` or `pwsh.exe`. Its `target.process.command_line` must contain an encoded-command flag **or** a hidden-window flag.
  - `$connection`: a `NETWORK_CONNECTION` from the **same process instance** (`principal.process.product_specific_process_id`) to an IP outside private and loopback ranges, at or after the launch.
  - `$file_write`: an optional `FILE_CREATION` by the same process instance.
- **Window:** `match: $hostname, $powershell_process_id over 5m`.
- **Condition:** `$powershell and $connection and #file_write >= 0`.
  - The launch context and an external connection are required.
  - Created files are optional context (unbounded condition).
- **PowerShell alone never matches:** the Office parent, an obfuscation or hiding flag, **and** follow-on network activity by that process are all required.
- **What the rule does not express:**
  - DNS queries.
  - "A file created by PowerShell was then executed".
  - PowerShell's full parameter-prefix matching. The regex only covers the common spellings (`-e`, `-ec`, `-en`, `-enc`, `-encodedcommand`; `-w`, `-win`, `-window`, `-windowstyle` followed by `hidden`).
  - A rule *can* chain more events. This one stays readable and avoids requiring telemetry that many parsers don't populate.
- **Severity `Medium`:** the minimum evidence (an Office parent plus one flag plus an external connection) corresponds to MEDIUM in the Python engine. Python raises the dataset's case to HIGH because it also sees the file creation, the execution of that file and that file's own connection.
- **Likely false positives:** approved Office add-ins or macros that call PowerShell, and management tools that use encoded commands.
- **Telemetry assumptions:**
  - The parser fills `principal.process` / `target.process` as the UDM usage guide describes.
  - It provides a stable `product_specific_process_id` (for example the Sysmon ProcessGuid) on launch, network and file events.
  - If it doesn't, the join must fall back to `pid` plus hostname. PIDs are reused, which is why the Python engine combines PID, host, image and a time window.

### 3. Payload Download and Execution

[`detections/payload_download_execution.yaral`](../detections/payload_download_execution.yaral)

- **Events (all share `$hostname` and `$user`):**
  - `$download`: a `PROCESS_LAUNCH` of `curl` or `wget` whose command line contains a URL that is not localhost or a private range. `re.capture()` extracts the output path (`-o`, `--output`, `-O`, `--output-document`, including clustered flags such as `-sLo`) into `$payload_path`.
  - `$permission_change`: a `FILE_MODIFICATION` by `chmod` on exactly `$payload_path`.
  - `$execution`: a `PROCESS_LAUNCH` whose `target.process.file.full_path` is exactly `$payload_path`.
  - `$outbound`: an optional `NETWORK_CONNECTION` by the executed file to an external IP.
- **Order:** download, then permission change, then execution, then the optional connection.
- **Window:** `match: $hostname, $user over 15m`.
- **Condition:** `$download and $permission_change and $execution and #outbound >= 0`.
- **Execution evidence is required.** A download on its own, or a download plus `chmod`, never matches.
- **Severity `High`:** this matches Python's HIGH case (download, then permission change, then execution of the same file). Python also reports a MEDIUM variant without `chmod`; that would be a separate, lower-severity rule.
- **Likely false positives:** install scripts (`curl -o /tmp/install.sh && chmod +x ... && ./install.sh`), CI/DevOps automation, and administrators running legitimate installers.
- **Telemetry assumptions:**
  - The endpoint source records full command lines.
  - Permission changes are logged as `FILE_MODIFICATION` with `principal.process` set to `chmod` (for example auditd or EDR file events).
  - Executions have `target.process.file.full_path` set to the executed file.
  - If permission changes only appear as `chmod` process launches, the permission event would need its own `re.capture()` of the path instead.
  - `wget -o` (lowercase) writes a *log* file. The capture pattern would also pick that path up, but it would only matter if that log file were then executed.

## MITRE ATT&CK Note

The rules use only the mappings already justified in `src/mitre.py`, limited to the technique each rule **always** requires. Tactic IDs were checked on attack.mitre.org.

| Rule | `tactic` | `technique` | Conditional techniques from the Python mapping (not in metadata) |
|---|---|---|---|
| Credential attack | TA0006 Credential Access | T1110 Brute Force | none |
| Suspicious PowerShell | TA0002 Execution | T1059.001 PowerShell | T1027.010 (if `-EncodedCommand`), T1564.003 (if hidden window), T1105 (if a file is created after the external connection) |
| Payload execution | TA0011 Command and Control | T1105 Ingress Tool Transfer | T1059.004 (if the parent of the execution is a Unix shell) |

**Discrepancy for review (Python unchanged):**
- Google's official community rules map "repeated failures then success" to **T1110.001** (Password Guessing) (`win_repeatedAuthFailure_thenSuccess_T1110_001`), and "failures across many users" to **T1110.003** (Password Spraying) (`rw_windows_password_spray_T1110_003`).
- This project keeps the parent **T1110**, because the telemetry cannot show which passwords were tried. That is a deliberate, more conservative choice, not an error in either source.
- Note that T1105 sits under the *Command and Control* tactic in ATT&CK. Using it does not claim that any connection was command-and-control.

## Validation

### Static checks (performed)
`tests/test_yaral_static.py` checks only the rule **files**:
- the three files exist, are referenced from this document and the README, and use unique rule names
- each rule has the `meta`, `events`, `match`, `outcome` and `condition` sections, in that order
- `meta` contains the required keys, a valid severity and the expected ATT&CK technique
- every event variable used in `events` also appears in `condition`
- no placeholder values (`TODO`, `TBD`, `changeme` ...), and the "not validated in a live tenant" disclaimer is present

### Live validation (not performed)
- **The official route:** the Google SecOps API method `verifyRuleText` checks whether a rule is valid YARA-L without creating or running it. Google's `content_manager` tool in the official `chronicle/detection-rules` repository uses it.
- **Why it wasn't done:** it requires a Google SecOps instance and Google Cloud credentials. No official offline or standalone YARA-L validator was found, so **no syntax validation by Google SecOps has taken place**.
- **What the static tests do not prove:** they don't show that Google SecOps would accept or correctly evaluate these rules.

## Limitations

- **No tenant:**
  - No Google SecOps tenant was available.
  - The rules were not compiled or verified (`verifyRuleText`), not deployed, and not run against any data in Google SecOps.
  - No alerts, detections or screenshots from Google SecOps exist for them.
- **Parser-dependent fields:**
  - UDM field availability depends on the parser and the source telemetry.
  - Values such as `security_result.action` (`BLOCK` vs `FAIL`), `target.hostname` on logins, `product_specific_process_id`, and `FILE_MODIFICATION` events for `chmod` may be missing or mapped differently for a given log type.
- **Sources:** the syntax was written against current official documentation (pages retrieved 2026-10-05) and official example rules. Where a construct is used, an official example uses the same construct (for example `re.regex(...) nocase`, timestamp ordering between events, `#placeholder` counts and `net.ip_in_range_cidr`).
- **Before production use:**
  - Verify each rule in a live tenant, confirm the field mappings for the actual log types, and test it against known-good and known-bad data.
  - Tune the windows and thresholds.
  - Consider reference lists for allow-listing (for example approved installers or admin scripts).
- **Not line-for-line ports:** where a translation would be inaccurate or depend on rarely populated fields, the rule expresses the behavior more simply, and the walkthrough above says so.

## Official References

Google SecOps documentation (retrieved 2026-10-05; `cloud.google.com/chronicle/docs/...` URLs now redirect to `docs.cloud.google.com`):

- Get started with YARA-L (served at the former YARA-L 2.0 syntax URL): https://docs.cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax
- Meta section syntax: https://docs.cloud.google.com/chronicle/docs/yara-l/meta-syntax
- Events section syntax: https://docs.cloud.google.com/chronicle/docs/yara-l/events-syntax
- Match section syntax: https://docs.cloud.google.com/chronicle/docs/yara-l/match-syntax
- Outcome section syntax: https://docs.cloud.google.com/chronicle/docs/yara-l/outcome-syntax
- Condition section syntax: https://docs.cloud.google.com/chronicle/docs/yara-l/condition-syntax
- Expressions, operators, and other constructs: https://docs.cloud.google.com/chronicle/docs/yara-l/expressions
- Functions: https://docs.cloud.google.com/chronicle/docs/yara-l/functions
- Single and multiple event rules (examples): https://docs.cloud.google.com/chronicle/docs/yara-l/yara-l-2-0-examples
- UDM field list: https://docs.cloud.google.com/chronicle/docs/reference/udm-field-list
- UDM usage guide (required fields per event type, principal/target): https://docs.cloud.google.com/chronicle/docs/unified-data-model/udm-usage

Official Google example rules and tooling (`chronicle/detection-rules`, maintained by Google Cloud Security):

- Repository and style guide: https://github.com/chronicle/detection-rules and https://github.com/chronicle/detection-rules/blob/main/STYLE_GUIDE.md
- `rules/community/microsoft/windows/win_repeatedAuthFailure_thenSuccess_T1110_001.yaral`
- `rules/community/microsoft/windows/rw_windows_password_spray_T1110_003.yaral`
- `rules/community/okta/okta_multiple_users_logins_with_invalid_credentials_from_the_same_ip.yaral`
- `rules/community/microsoft/windows/base64_encoded_powershell_command_detected.yaral`
- `rules/community/network/high_risk_user_download_executable_from_macro.yaral`
- `tools/content_manager/README.md` (rule verification through the Google SecOps API)

MITRE ATT&CK (tactics checked 2026-10-05): https://attack.mitre.org/tactics/TA0006/, https://attack.mitre.org/tactics/TA0002/, https://attack.mitre.org/tactics/TA0011/. Technique pages were verified when the ATT&CK mappings were written (see `src/mitre.py`).
