# CLAUDE.md — SecOps Automation Lab

## Project

This repository contains **SecOps Automation Lab**, a small cybersecurity portfolio and learning project focused on:

- Detection Engineering
- Security Automation
- Security telemetry
- Log normalization
- Event correlation
- MITRE ATT&CK
- Threat Intelligence
- Risk scoring
- SOAR concepts
- Python and security APIs
- Google SecOps concepts
- YARA-L examples

The project is intended for a **Junior Detection Engineering / Security Automation technical interview**.

The priority is:

1. Technical correctness
2. Explainability
3. Security reasoning
4. Readability
5. Simplicity

Do not optimize for feature count or architectural complexity.

---

# Git Policy — CRITICAL

The repository owner controls ALL Git and GitHub operations.

Claude MUST NOT perform Git write operations.

## Forbidden

Do NOT execute:

- `git init`
- `git add`
- `git commit`
- `git push`
- `git pull`
- `git merge`
- `git rebase`
- `git reset`
- `git switch`
- `git checkout` when it modifies repository state
- `git tag`

Do NOT:

- create branches
- delete branches
- modify remotes
- modify Git configuration
- initialize repositories
- create GitHub repositories
- create Pull Requests
- merge Pull Requests
- interact with GitHub on behalf of the repository owner
- automatically commit changes

## Allowed read-only Git operations

Claude may use:

- `git status`
- `git diff`
- `git log`

when useful for inspecting the repository.

At the end of each implementation phase:

1. List files created.
2. List files modified.
3. Report test results.
4. Suggest one conventional commit message.
5. STOP.

The repository owner will manually review, stage, commit and push all changes.

---

# Development Philosophy

This is NOT a production SIEM.

Do not pretend that it is.

This is an educational Detection Engineering and Security Automation laboratory.

Prefer small, understandable implementations over enterprise architecture.

Avoid unnecessary:

- frameworks
- services
- databases
- containers
- cloud infrastructure
- abstraction layers
- design patterns
- class hierarchies
- dependencies

Every important piece of code should be understandable and defensible during a technical interview.

---

# Python

Use modern Python 3.

Prefer:

- type hints
- `pathlib`
- dataclasses where they genuinely improve the model
- small functions
- descriptive names
- explicit control flow
- standard library functionality

Use external dependencies only when they provide clear value.

Avoid clever or unnecessarily compressed Python.

Readability is more important than minimizing line count.

---

# Testing

All important detection and normalization behavior should be testable.

Use `pytest`.

Tests must:

- run locally
- not require internet access
- not require API credentials
- not depend on external infrastructure
- test meaningful behavior

When implementing security detections, include both:

- positive malicious/suspicious scenarios
- benign scenarios that should NOT trigger

False-positive awareness is an important project goal.

---

# Security Telemetry

Security telemetry used by the project is simulated.

Never imply that simulated telemetry came from a real organization.

Include realistic:

- authentication events
- process creation
- network connections
- DNS queries
- file events
- Windows activity
- Linux activity

Include benign noise.

Not every event should be suspicious.

---

# Security Reasoning

Do not make claims stronger than the available evidence.

Examples:

A failed login does NOT automatically mean brute force.

Multiple usernames attacked from one IP do NOT automatically prove password spraying unless password reuse is actually observable.

PowerShell is NOT inherently malicious.

`curl` and `wget` are NOT inherently malicious.

An external network connection does NOT automatically prove command-and-control.

A downloaded executable does NOT mean it was executed unless execution telemetry exists.

An outbound connection does NOT automatically prove data exfiltration.

Use language such as:

- suspicious
- potentially
- consistent with
- may indicate
- possible
- requires further investigation

when evidence is incomplete.

Correlation should increase confidence.

---

# Windows

When interpreting Windows telemetry, distinguish between:

- file creation
- process creation
- network activity
- DNS activity
- authentication
- command execution

Important Windows processes/tools may include:

- `powershell.exe`
- `cmd.exe`
- `WINWORD.EXE`
- `OUTLOOK.EXE`
- `rundll32.exe`
- `certutil.exe`
- `schtasks.exe`
- `reg.exe`

Do not classify them as malicious based solely on process name.

Context matters.

---

# Linux

When interpreting Linux telemetry, understand common commands such as:

- `curl`
- `wget`
- `chmod`
- `chown`
- `ssh`
- `scp`
- `bash`
- `sh`
- `whoami`
- `id`
- `hostname`
- `uname`
- `cat`
- `ps`
- `ss`
- `ip`
- `rm`

Distinguish:

download
→ permission modification
→ execution
→ network communication
→ cleanup

Do not describe normal shell commands as syscalls.

---

# Normalization

The project will use a small vendor-neutral internal event schema.

It may be conceptually inspired by normalized SIEM schemas such as Google SecOps UDM.

However:

**The internal schema is NOT Google UDM.**

Never describe it as Google UDM.

Raw vendor events should be preserved alongside normalized representations where practical.

---

# Google SecOps

Google SecOps concepts may be represented in documentation and detection examples.

Important concepts include:

- SIEM
- UDM
- normalized telemetry
- search
- detection engineering
- YARA-L 2.0
- investigation
- SOAR
- playbooks

Unless a real Google SecOps tenant becomes available:

- do not claim Google SecOps integration
- do not claim YARA-L rules were deployed
- do not claim YARA-L rules were executed
- do not fabricate screenshots
- do not fabricate detection results

YARA-L files are portfolio/learning examples based on official documentation.

---

# MITRE ATT&CK

MITRE ATT&CK mappings must be technically justified.

Each mapping should contain:

- technique ID
- technique name
- reason/evidence

Do not map techniques merely because they sound related.

When uncertain, verify the current MITRE ATT&CK documentation before including a mapping.

---

# Threat Intelligence

Threat Intelligence enrichment will eventually support:

1. deterministic mock provider
2. optional real external API provider

The project MUST work without:

- internet
- API keys
- external services

Mock enrichment must always be clearly labeled as simulated.

Secrets must never be committed.

Use environment variables for real API credentials.

`.env` must remain ignored by Git.

---

# Security Automation / SOAR

All response actions in this laboratory are simulated.

Examples:

- block IP
- disable account
- isolate endpoint
- escalate incident

Never modify real:

- firewalls
- endpoints
- identity providers
- user accounts
- production infrastructure

Clearly distinguish between:

- detection
- investigation
- recommendation
- simulated automated response

---

# Architecture

The intended final pipeline is:

```text
Simulated Security Telemetry
            |
            v
       Normalization
            |
            v
     Detection Engine
            |
            v
    MITRE ATT&CK Mapping
            |
            v
 Threat Intelligence Enrichment
            |
            v
       Risk Engine
            |
            v
    SOAR-style Playbook
            |
            v
      Incident Report