# Interview Guide

A technical review sheet for this repository: short answers to the questions a reviewer is likely to ask, each tied to where it lives in the code, plus a 2–3 minute demo flow. Every answer describes what this lab does. None of it is a claim of production experience.

## Demo Flow (2–3 minutes)

1. **Architecture (20 s).** Open the README Mermaid diagram. Telemetry → normalization → detection → enrichment → risk → incident → simulated playbook. Google SecOps / YARA-L sits alongside as a conceptual mapping and is not executed.
2. **Run (10 s).** `python main.py --incidents-only`. Three incidents: one CRITICAL, two HIGH.
3. **One incident (40 s).** *Possible Payload Execution on Linux Host*: `curl` downloads `/tmp/.cache-update`, `chmod +x`, execution, then an outbound connection. The point is that each step is normal on its own; the correlation on one file, host and user is the signal.
4. **Evidence (20 s).** `python main.py --no-timeline` shows the six evidence event IDs. `python main.py --inspect cc5d2ecdd2ac` shows the execution event, including its preserved raw event.
5. **Risk contributors (30 s).** 98 = 38 evidence + 25 execution + 10 outbound + 15 related credential-attack detection + 10 threat intel. Without the mock threat intel it is still 88, so the threat intel is context, not the deciding factor.
6. **Playbook (20 s).** `[SIMULATED ACTION]` isolation and IP block. Automation only happens at CRITICAL with confidence ≥ 0.80. The two HIGH incidents only get *recommendations* that need analyst approval.
7. **YARA-L (30 s).** Open `detections/payload_download_execution.yaral`: events joined on `$hostname`, `$user` and `$payload_path`, `match ... over 15m`, and `condition: $download and $permission_change and $execution`. Say clearly that it was written from the official docs, but not validated in a tenant; `verifyRuleText` in a live Google SecOps instance is still needed.

## Questions and Answers

### 1. What does this project do?
It simulates Windows and Linux telemetry (45 events, 5 log formats). It normalizes the events into one schema and runs three behavioral detections that correlate multiple events. Each detection gets ATT&CK and threat-intelligence enrichment, then an explainable incident risk score, and finally a SOAR-style playbook whose actions are all simulated. It runs offline with deterministic output, and 286 tests cover it.

### 2. Why normalize telemetry?
Products name the same thing differently (`src_ip`, `source_address`, `SourceIp`) and use different timestamp formats (ISO with offset, epoch milliseconds, naive UTC). Normalizing first means the detection logic is written once against one schema instead of once per vendor. `src/normalizer.py` also keeps the raw event on every normalized event, because analysts sometimes need vendor fields that the schema dropped.

### 3. What is behavioral detection?
Detecting a *pattern of activity* rather than a single indicator or tool name. For example: download → permission change → execution of the same file by the same user on the same host. Indicators such as IPs and hashes change easily, while behavior is harder for an attacker to avoid. The detectors don't hardcode IPs, usernames or event IDs.

### 4. Why is PowerShell not automatically malicious?
It is a standard administration tool. The dataset includes benign `Get-Service` admin usage. Even `-EncodedCommand` and hidden windows are used by legitimate management software. The PowerShell detection needs suspicious launch context (an Office parent, encoding, a hidden window) and only becomes HIGH when the *same process* also does correlated follow-on activity. PowerShell without suspicious context is ignored, even if it makes network connections.

### 5. How does the credential detection work?
For each successful login, it collects failed logins from the **same source IP to the same host** in the 5 minutes before it. It fires if there are at least 5 failures across at least 3 distinct accounts. Failures used by one detection aren't reused, so one burst produces one detection. Confidence is 0.70 base, +0.10 if the source IP is external, and +0.10 if the account that succeeded had failed earlier in the burst.

### 6. Why don't you call it password spraying?
Password spraying (T1110.003) means trying one or a few passwords across many accounts. The login events show which accounts were tried, not which passwords, so spraying can't be told apart from guessing (T1110.001). The detection says "credential attack" and maps to the parent technique T1110. Google's community rules use the sub-techniques for similar logic; this project deliberately makes the more conservative choice.

### 7. How does event correlation work?
Every detector joins events on explicit keys and a time window, using parsed UTC timestamps (input order doesn't matter):
- **Credential attack:** source IP + target host.
- **PowerShell:** host + PID + process image. PIDs get reused, so a PID is never trusted alone. A "created file executed" signal needs a child of *that* PowerShell process running the *exact* path it created.
- **Payload:** host + user + exact file path, with ordering enforced (download → chmod → execution → network).

The tests include negative cases: another host, another user, another PID, a mismatched path, the wrong order, or outside the window.

### 8. What is the difference between download and execution?
A download writes a file. Execution is a process started from that file, and it needs its own telemetry (a process-creation event whose image is the downloaded path). The payload detection **requires** execution evidence: download alone, or download plus `chmod`, never fires. Evidence entries are labelled `DOWNLOAD`, `PERMISSION`, `EXECUTION` and `NETWORK` separately.

### 9. Detection confidence vs incident risk?
- **Confidence:** how sure we are that the pattern happened. It is a documented sum of signal weights, capped at 0.95.
- **Risk:** how concerning the incident is, given the evidence and context. It is 0–100 across four capped categories: evidence (confidence × 40), observed outcome (account access, execution, outbound connection), related detections on the same host and user, and threat intel (max 10).
- **No double counting:** launch-context signals count only through confidence, and outcome stages don't stack.

### 10. What is MITRE ATT&CK used for?
It is a shared vocabulary for adversary behavior. It helps with communication, coverage analysis and pivoting to documented procedures and mitigations. It is **not** a severity scale, and a mapping doesn't prove intent. `src/mitre.py` adds a technique only when specific evidence supports it. For example, T1105 for the payload requires an external download source, and T1059.004 requires that the parent of the execution was a Unix shell. Techniques that were considered and rejected (T1078, T1566.001, T1204.002, T1222.002, T1071, T1041) are documented with reasons in `docs/design.md`.

### 11. What does threat intelligence add?
Context about indicators: has this IP been reported, and how often? It helps analysts prioritize. It doesn't replace evidence: `MALICIOUS` doesn't prove compromise, and `UNKNOWN` doesn't mean safe. In the risk engine it is worth at most 10 of 100 points, `UNKNOWN`, `BENIGN` and failed lookups never lower the score, and it can never be the only reason for CRITICAL.

### 12. Why use a mock threat-intel provider?
So the project runs offline, deterministically and without credentials, which matters for tests and for an interview demo. The simulated attacker IPs are documentation addresses (RFC 5737), so no real intelligence about them exists anyway. Mock results are labelled `Mock Threat Intelligence (simulated)` with `simulated: true` everywhere, so they can't be mistaken for real data.

### 13. How does the AbuseIPDB API integration work?
1. Select it explicitly with `--threat-intel abuseipdb`. The key is read from `ABUSEIPDB_API_KEY`.
2. For each external IP in a detection, the cache is checked first. Non-public addresses are refused before any request.
3. The request is `GET https://api.abuseipdb.com/api/v2/check` with `ipAddress` and `maxAgeInDays`, the `Key` header and a 10-second timeout.
4. The status code is checked, the JSON is parsed, and `data.abuseConfidenceScore` must be present and valid.
5. The response becomes a structured `ThreatIntelResult`. The score thresholds (75 malicious, 25 suspicious) are this project's choice.

### 14. What happens if the API fails?
The provider raises a `ThreatIntelError` subtype with a message written by the code: missing key, 401/403, 429 with `Retry-After`, other statuses, timeout, connection error, invalid JSON or missing fields. Library exception text is not passed on, so the key can't leak. `CachedThreatIntel` turns the error into an `UNAVAILABLE` result, so the detections, ATT&CK mappings and incidents are still produced. The failure is cached for the run, so a rate-limited API isn't called again. All of this is tested with faked HTTP responses.

### 15. What is SOAR?
Security Orchestration, Automation and Response: platforms that take alerts, enrich them, open cases and run playbooks (sequences of decisions and actions) across security tools. Here, `src/playbook.py` is a small, explicit policy table: record, escalate, and recommend or simulate containment, per risk level and per affected entity.

### 16. Why are response actions simulated?
It is a lab, and a wrong automated action has real consequences. No code path calls a firewall, EDR or identity system. `PlaybookAction.simulated` can't be set to false, and a static test checks that the response modules import nothing that can run commands or open connections. The design still separates recommendations (need approval) from automated actions (simulated here). Automation also requires CRITICAL risk *and* confidence ≥ 0.80, so a weaker detection can't trigger it.

### 17. Why might server isolation require approval?
Isolating `web-prod-01` takes a production service offline. If the detection is a false positive (for example an install script), the response causes an outage. A real decision weighs asset criticality, business impact, redundancy and evidence quality, and often a human signs off. The lab has no asset inventory, so it can't make that judgment, and this is listed as a limitation.

### 18. What is Google SecOps?
Google Cloud's security operations platform. It has a SIEM side (ingests telemetry, normalizes it to UDM, search and YARA-L detection rules) and SOAR capabilities (cases, playbooks). This project doesn't integrate with it and was not run on it.

### 19. What is UDM?
The Unified Data Model: Google SecOps' normalized event schema. Parsers map each log type into it. An event has `metadata` (for example `event_type = "USER_LOGIN"`) and nouns such as `principal` (the initiator) and `target` (the entity acted on), with fields like `principal.ip`, `target.user.userid`, `target.process.command_line` and `target.file.full_path`. In a `PROCESS_LAUNCH`, `principal.process` is the parent and `target.process` is the launched process.

### 20. What is YARA-L?
Google SecOps' detection rule language (YARA-L 2.0):
- `meta`: descriptive metadata.
- `events`: filters and joins over UDM fields, using event variables and placeholder variables.
- `match`: grouping keys plus a time window, 1 minute to 48 hours.
- `outcome`: aggregated context for the analyst.
- `condition`: when the rule fires, for example `#failed_login >= 5 and $successful_login`.

### 21. How does the local project map conceptually to Google SecOps?
| Local | Google SecOps |
|---|---|
| `security_events.json` | ingested telemetry |
| `normalizer.py` → `NormalizedEvent` | parser → UDM |
| `detection_engine.py` | YARA-L rules |
| `Detection` | detection / alert |
| `enrichment.py`, `threat_intel.py` | investigation and enrichment |
| `playbook.py` | SOAR playbooks |

These are analogies. `NormalizedEvent` is not UDM, and the Python code is not a YARA-L engine.

### 22. Were the YARA-L rules tested in Google SecOps?
**No.** No tenant was available. They were written against current official documentation and Google's official example rules, which use the same constructs. The only tests are static file checks: sections, metadata, consistency with the Python mappings, and that every event variable appears in the condition. Real validation would be `verifyRuleText` through the Google SecOps API, then testing against real parsed data. UDM field availability (for example `product_specific_process_id`, or `BLOCK` vs `FAIL` for failed logins) depends on the parser.

### 23. What are the biggest limitations?
- **Data:** simulated and small, so the detections were never measured against real noise.
- **Scoring:** the weights are illustrative, not tuned.
- **Context:** no asset or identity context, no persistence or case management.
- **Integrations:** none for real response, and the YARA-L rules are unvalidated.

### 24. What would you build next in a production environment?
- **Data:** real log sources through proper parsers (or ingest into a SIEM such as Google SecOps and keep the rules there).
- **Context:** asset inventory and criticality, and identity context (service accounts, privileged users), so the risk score and playbook can tell a production server from a lab VM.
- **Tuning:** measure false-positive rates on real data, add allow-lists or reference lists for known installers and admin scripts, and add baselines.
- **Detection as code:** version-controlled rules, CI that runs `verifyRuleText` and replays test data, and a review process.
- **Incidents:** correlate related detections into one incident (the credential attack and the payload run here are the same intrusion), with persistent case state.
- **Response:** real SOAR integrations behind approval workflows, audit logging and rollback, starting with low-impact actions.
