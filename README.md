# Purple Team Automation Framework

### Simulated Attack Telemetry | MITRE ATT&CK Mapped | Sigma Rule Coverage Scoring

**Author:** Kushagra Patel

> **Status.** The first design of this project used an LLM to write the Sigma rule for each run. The current code does not call an LLM. The Blue Engine returns one pre-written Sigma rule per technique and the whole pipeline runs offline. LLM generation is listed under future work.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Problem Statement](#2-problem-statement)
3. [Architecture](#3-architecture)
4. [MITRE ATT&CK Coverage](#4-mitre-attck-coverage)
5. [Folder Structure](#5-folder-structure)
6. [Tech Stack](#6-tech-stack)
7. [How It Works — Pipeline Flow](#7-how-it-works--pipeline-flow)
8. [Setup & Installation](#8-setup--installation)
9. [Running the Framework](#9-running-the-framework)
10. [API Reference](#10-api-reference)
11. [Dashboard](#11-dashboard)
12. [Sample Output](#12-sample-output)
13. [Design Decisions](#13-design-decisions)
14. [Limitations & Future Work](#14-limitations--future-work)
15. [Academic References](#15-academic-references)

---

## Recent Improvements

- **Fixed CORS bug** — `allow_credentials=True` combined with `allow_origins=["*"]` is rejected by browsers; changed to `allow_credentials=False` so the dashboard can call the API correctly.
- **Made `/techniques` endpoint dynamic** — previously hardcoded a list of 7 techniques that could silently drift out of sync; now built automatically from `TECHNIQUE_DETAILS` in `config.py` so one dict is the single source of truth.
- **Made `DEMO_MODE` configurable** — was hardcoded `True` in code; now reads from `.env` (`DEMO_MODE=true/false`) so it can be toggled without changing source files.
- **Fixed `datetime.utcnow()` deprecation** — replaced in `red_engine.py` and `artifact_store.py` with `datetime.now(timezone.utc)` (Python 3.12+ compatible).
- **Removed dead `MockBlueEngine` class** — `BlueEngine` never used it (only imported `_SIGMA_RULES`); removed to keep the file clean.
- **Fixed 4 failing tests** — replaced `TestBlueEngineMocked` (patched a non-existent API client) with `TestBlueEngine` that tests the real offline engine directly; replaced `test_max_tokens_is_positive` (imported an undefined config value) with a test that verifies `TECHNIQUE_DETAILS` and `SUPPORTED_TECHNIQUES` stay in sync.

---

## 1. Project Overview

This project implements a **Purple Team Automation Framework** that connects adversary simulation (Red Team) and detection engineering (Blue Team) in one automated pipeline.

The framework simulates attack telemetry for seven MITRE ATT&CK techniques, pairs each technique with a pre-written Sigma detection rule, and then scores that rule against the simulated logs to measure detection coverage — all in a single API call.

**Core Idea:** A traditional Purple Team exercise requires manual effort from both Red and Blue teams working together. This framework automates the repeatable parts of that cycle — log generation, rule lookup and coverage validation — so one run completes in seconds and produces the same documented result every time.

---

## 2. Problem Statement

Security Operations Centers (SOCs) rely on detection rules to identify attacks. Writing these rules is time-consuming and requires deep expertise. At the same time, adversaries continuously evolve their techniques. The result is a persistent gap between what attackers can do and what defenders can detect.

Purple Team exercises exist to close this gap, but they require coordinated effort between red and blue teams, are expensive to run frequently, and produce inconsistent documentation.

**This framework addresses:**
- The manual overhead of simulating attack telemetry for detection testing
- Keeping a Sigma rule next to the telemetry it is meant to catch, for each technique
- The lack of automated feedback on whether a detection rule actually works
- The absence of a repeatable, documented pipeline for Purple Team operations

---

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  PURPLE TEAM AUTOMATION FRAMEWORK               │
│                                                                  │
│  ┌──────────────┐     ┌──────────────┐     ┌────────────────┐  │
│  │  RED ENGINE  │────▶│ BLUE ENGINE  │────▶│   VALIDATOR    │  │
│  │              │     │              │     │                │  │
│  │  Adversary   │     │  Pre-written │     │  Coverage      │  │
│  │  Simulation  │     │  Sigma Rule  │     │  Scoring       │  │
│  │  (T-Codes)   │     │  Lookup      │     │  PASS/WARN/FAIL│  │
│  └──────────────┘     └──────────────┘     └────────────────┘  │
│         │                    │                      │           │
│         └────────────────────┴──────────────────────┘          │
│                              │                                  │
│                    ┌─────────────────┐                         │
│                    │  ORCHESTRATOR   │                         │
│                    │  (Pipeline Ctrl)│                         │
│                    └─────────────────┘                         │
│                              │                                  │
│              ┌───────────────┴───────────────┐                 │
│              │                               │                  │
│     ┌─────────────────┐           ┌──────────────────┐        │
│     │  FastAPI Server │           │  Artifact Store  │        │
│     │  REST Endpoints │           │  JSON + YAML I/O │        │
│     └─────────────────┘           └──────────────────┘        │
│                    │                                            │
│           ┌─────────────────┐                                  │
│           │  HTML Dashboard │                                   │
│           │  (Browser UI)   │                                   │
│           └─────────────────┘                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Component Summary

| Component | File | Responsibility |
|---|---|---|
| Red Engine | `app/engines/red_engine.py` | Simulates attack telemetry for MITRE techniques |
| Blue Engine | `app/engines/blue_engine.py` | Returns the pre-written Sigma rule for the technique and parses it into a `SigmaRule` model. The rules live in `mock_blue_engine.py`. No API is called |
| Validator | `app/engines/validator.py` | Scores Sigma rule coverage against telemetry logs |
| Orchestrator | `app/engines/orchestrator.py` | Runs the full pipeline in sequence |
| Schema | `app/schema/schema.py` | Pydantic v2 data models for all pipeline stages |
| Artifact Store | `app/store/artifact_store.py` | Saves pipeline results and rules to disk |
| API Server | `main.py` | FastAPI REST server exposing pipeline endpoints |
| Dashboard | `dashboard.html` | Browser-based UI for running and monitoring pipelines |

---

## 4. MITRE ATT&CK Coverage

| Technique ID | Name | Tactic | Log Source | Event ID |
|---|---|---|---|---|
| T1059.001 | PowerShell Execution | Execution | PowerShell Operational | 4104 |
| T1003.001 | LSASS Memory Dump | Credential Access | Sysmon | 10 |
| T1547.001 | Registry Run Key Persistence | Persistence | Sysmon | 13 |
| T1055.001 | DLL Injection | Defense Evasion / Privilege Escalation | Sysmon | 8 |
| T1078 | Valid Accounts — Stolen Credential Logon | Initial Access / Persistence | Windows Security | 4624 |
| T1082 | System Information Discovery | Discovery | Sysmon / Process | 1 |
| T1071.001 | C2 over Web Protocols | Command & Control | Sysmon Network | 3 |

Each technique simulates realistic Windows telemetry using field values drawn from known attacker tooling (Mimikatz, Procdump, encoded PowerShell cradles).

---

## 5. Folder Structure

```
PURPLE_TEAM_FRAMEWORK/
│
├── app/
│   ├── engines/
│   │   ├── __init__.py
│   │   ├── red_engine.py           # Adversary simulation — generates synthetic telemetry
│   │   ├── blue_engine.py          # Looks up and parses the Sigma rule for a technique
│   │   ├── mock_blue_engine.py     # The pre-written Sigma rules, one per technique
│   │   ├── orchestrator.py         # Pipeline controller (Red → Blue → Validate)
│   │   └── validator.py            # Coverage scoring engine
│   │
│   ├── schema/
│   │   ├── __init__.py
│   │   └── schema.py               # Pydantic v2 data models (all stages)
│   │
│   └── store/
│       ├── __init__.py
│       └── artifact_store.py       # Saves JSON results and Sigma YAML to disk
│
├── logs/                           # Pipeline run results (auto-generated, not committed)
├── rules_output/                   # Generated Sigma rules (auto-generated, not committed)
├── notebooks/                      # Jupyter notebooks (demo and experiments)
├── tests/                          # Unit tests
│
├── main.py                         # FastAPI application entry point
├── dashboard.html                  # Browser-based monitoring dashboard
├── requirements.txt                # Python dependencies
├── .env.example                    # Environment variable template
├── .env                            # Local settings (NOT committed to repo)
├── .gitignore
└── README.md
```

---

## 6. Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Language | Python 3.11+ | Core framework |
| API Framework | FastAPI | REST server and OpenAPI docs |
| Data Validation | Pydantic v2 | Request/response schema enforcement |
| Detection Format | Sigma | Vendor-neutral detection rule standard |
| YAML Parsing | PyYAML | Parsing the Sigma rules |
| Frontend | HTML / Vanilla JS | Dashboard (no framework dependency) |
| Server | Uvicorn | ASGI server for FastAPI |
| Testing | pytest | Unit tests |
| Config | python-dotenv | Environment variable management |

---

## 7. How It Works — Pipeline Flow

### Stage 1: Red Engine (Adversary Simulation)

The Red Engine accepts a MITRE ATT&CK technique ID and generates `N` synthetic Windows telemetry logs that mimic what a real attack would produce. No actual malicious code is executed — all output is simulated data.

For `T1059.001` (PowerShell), it generates Event ID 4104 logs with realistic encoded commands and download cradles. For `T1003.001` (LSASS), it generates Sysmon Event ID 10 (process access) logs targeting `lsass.exe` with known tool names like `mimikatz.exe` and `procdump.exe`. All 7 techniques follow the same pattern, each with technique-specific field values drawn from real-world threat intelligence.

### Stage 2: Blue Engine (Sigma Rule Lookup)

The Blue Engine looks up the Sigma rule written for the requested technique. The seven rules are stored as YAML in `mock_blue_engine.py`, keyed by MITRE ATT&CK technique ID.

The engine parses the YAML, validates its structure, and maps it to a `SigmaRule` Pydantic model. A technique with no rule gets a clearly labelled placeholder. Nothing is sent to an external service, so the pipeline runs fully offline.

### Stage 3: Validator (Coverage Scoring)

The Validator extracts all detection keywords from the generated Sigma rule's `detection` block. It checks each telemetry log against those keywords, matching only against fields that Sigma rules target in a real SIEM (CommandLine, Image, TargetObject, etc.).

Coverage score is computed as `matched_logs / total_logs` and mapped to:
- `PASS` — ≥ 75% logs detected
- `WARN` — 50–74% detected
- `FAIL` — < 50% detected

### Stage 4: Artifact Storage

If `save_artifacts: true`, the full pipeline result is written as a JSON file to `logs/` and the Sigma rule is written as a `.yml` file to `rules_output/`. Both directories are excluded from version control.

---

## 8. Setup & Installation

### Prerequisites

- Python 3.11 or higher
- No API key is needed

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/kushagra-patel1011/llm-purple-team-automation.git
cd llm-purple-team-automation

# 2. Create and activate virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
```

### .env File

```
APP_ENV=development
LOG_LEVEL=INFO
RULES_OUTPUT_DIR=rules_output
LOGS_DIR=logs
```

> The pipeline runs fully offline. It uses the pre-written Sigma rules and makes no external calls.

---

## 9. Running the Framework

### Start the API Server

```bash
python main.py
```

Server starts at `http://localhost:8000`

### Access the Dashboard

Open `dashboard.html` in a browser **after** the API server is running. Opening the file directly without a running server will show "API offline".

### Access API Documentation

FastAPI generates interactive docs automatically:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### Run Tests

```bash
pytest tests/
```

---

## 10. API Reference

### `GET /`
Health check. Returns server status and supported techniques.

### `GET /health`
Returns server health and list of supported MITRE techniques.

### `GET /techniques`
Returns all supported MITRE ATT&CK techniques with names and tactics.

### `POST /pipeline/run`
Triggers the full Red → Blue → Validate pipeline.

**Request Body:**
```json
{
  "technique_id": "T1059.001",
  "log_count": 5,
  "save_artifacts": true
}
```

**Response:** Full `PipelineResult` including all stage outputs, coverage score, and Sigma rule YAML.

### `GET /runs`
Returns a paginated list of all previously saved pipeline runs. Supports `limit` (1–100, default 20) and `offset` (default 0) query parameters.

### `GET /runs/{pipeline_id}`
Returns the full result of a specific pipeline run by ID.

---

## 11. Dashboard

The HTML dashboard (`dashboard.html`) provides a browser-based interface to:

- Select a MITRE ATT&CK technique from all 7 supported options
- Set the number of telemetry logs to generate (1–50)
- Trigger the full pipeline with a single button
- View the Sigma rule with syntax highlighting
- See coverage score and PASS/WARN/FAIL status
- Browse pipeline run history

No build step or Node.js required — single static HTML file that calls the local FastAPI server.

---

## 12. Sample Output

### Sigma Rule (T1059.001 — PowerShell)

```yaml
title: Suspicious PowerShell Encoded Command Execution
id: a3f1c2d4-8b5e-4a9f-b2c1-7e3d6f9a0b1c
description: Detects PowerShell execution with encoded commands, hidden window, or download cradles indicative of T1059.001
status: experimental
level: high
logsource:
  product: windows
  service: powershell
detection:
  selection:
    EventID: 4104
    ScriptBlockText|contains:
      - '-EncodedCommand'
      - 'DownloadString'
      - '-WindowStyle Hidden'
      - 'IEX'
      - 'Net.WebClient'
  condition: selection
tags:
  - attack.execution
  - attack.t1059.001
```

### Coverage Result

```
Coverage Score  : 100.0%
Matched Logs    : 5 / 5
Status          : PASS
```

---

## 13. Design Decisions

**Why Sigma and not YARA or Snort?**
Sigma is the vendor-neutral standard for SIEM detection rules. It can be compiled to Splunk SPL, Elastic EQL, Microsoft Sentinel KQL, and others. Generating Sigma means the output is immediately usable in a real SOC environment without modification.

**Why are the rules pre-written instead of generated by an LLM?**
The first design prompted an LLM with sample logs and asked it for a Sigma rule. The current version uses one pre-written rule per technique. This makes every run repeatable and removes the need for an API key. Generating rules with an LLM would be an optional extra stage, and its output would still need checking against rules like these.

**Why simulate logs instead of using real ones?**
Using real attack logs would require executing actual malicious tools in a controlled lab environment, which is outside the scope of this project. Simulation using known IOC patterns from public threat intelligence (Mimikatz signatures, PowerShell cradle patterns) produces logs that are structurally identical to real ones from the perspective of a Sigma rule.

**Why is `rules_output/` excluded from version control?**
These are pipeline artifacts written on each run, not source code. The directory is created at runtime.

---

## 14. Limitations & Future Work

**Current Limitations:**
- Red Engine generates synthetic logs; it does not interface with real Windows event infrastructure
- Blue Engine does not generate rules. It returns one pre-written rule per technique, for seven techniques
- The rules and the simulated logs are built from the same known indicators, so coverage scores are optimistic. A PASS shows the pipeline works end to end, not that the rule would catch a real attack
- Validator models Sigma `contains` behaviour only — does not account for `not` conditions or multi-selection logic
- No authentication on the FastAPI server (development only)

**Planned Extensions:**
- Integrate with Elastic Stack to deploy generated Sigma rules directly into a real SIEM
- Add an optional LLM stage that drafts a Sigma rule from the telemetry, with the Validator result fed back for refinement
- Score rules against logs that were not written alongside them
- Replace synthetic log generation with Atomic Red Team test output via subprocess integration
- Add multi-technique chaining to simulate kill chain sequences
- Add TAXII/STIX export for threat intelligence sharing

---

## 15. Academic References

1. MITRE ATT&CK Framework — https://attack.mitre.org/
2. Sigma Rule Specification — https://github.com/SigmaHQ/sigma
3. Pydantic v2 Documentation — https://docs.pydantic.dev/
4. FastAPI Documentation — https://fastapi.tiangolo.com/
5. Sysmon Event ID Reference — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
6. Windows Security Event Log Reference — https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/

---

*All attack simulations are synthetic and do not interact with real systems or networks.*
