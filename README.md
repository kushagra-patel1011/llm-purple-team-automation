# LLM-Driven Purple Team Automation Framework

### Red-First Architecture | MITRE ATT&CK Mapped | LLM-Powered Detection Engine

**Author:** Kushagra Patel 

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

This project implements an **LLM-driven Purple Team Automation Framework** that bridges the gap between adversary simulation (Red Team) and detection engineering (Blue Team) using a fully automated pipeline.

The framework simulates cyberattacks mapped to MITRE ATT&CK techniques, feeds the resulting telemetry into a large language model to auto-generate Sigma detection rules, and then scores those rules against the simulated logs to measure detection coverage — all in a single API call.

**Core Idea:** A traditional Purple Team exercise requires manual effort from both Red and Blue teams working together. This framework automates the repetitive parts of that cycle — log generation, rule authoring, and coverage validation — reducing a process that typically takes hours to under 30 seconds.

---

## 2. Problem Statement

Security Operations Centers (SOCs) rely on detection rules to identify attacks. Writing these rules is time-consuming and requires deep expertise. At the same time, adversaries continuously evolve their techniques. The result is a persistent gap between what attackers can do and what defenders can detect.

Purple Team exercises exist to close this gap, but they require coordinated effort between red and blue teams, are expensive to run frequently, and produce inconsistent documentation.

**This framework addresses:**
- The manual overhead of simulating attack telemetry for detection testing
- The bottleneck of writing Sigma rules by hand for each technique
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
│  │  Adversary   │     │  LLM-Powered │     │  Coverage      │  │
│  │  Simulation  │     │  Sigma Rule  │     │  Scoring       │  │
│  │  (T-Codes)   │     │  Generation  │     │  PASS/WARN/FAIL│  │
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
| Blue Engine | `app/engines/blue_engine.py` | Calls LLM API to generate Sigma detection rules |
| Mock Blue Engine | `app/engines/mock_blue_engine.py` | Offline fallback with hardcoded Sigma rules (no API key needed) |
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
│   │   ├── blue_engine.py          # LLM API call — generates Sigma rules
│   │   ├── mock_blue_engine.py     # Offline fallback — hardcoded Sigma rules
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
├── .env                            # API keys (NOT committed to repo)
├── .gitignore
└── README.md
```

---

## 6. Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Language | Python 3.11+ | Core framework |
| API Framework | FastAPI 0.135 | REST server and OpenAPI docs |
| AI / LLM | Anthropic Claude (claude-sonnet) | Sigma rule generation |
| Data Validation | Pydantic v2 | Request/response schema enforcement |
| Detection Format | Sigma | Vendor-neutral detection rule standard |
| YAML Parsing | PyYAML | Parsing LLM Sigma output |
| Frontend | HTML / Vanilla JS | Dashboard (no framework dependency) |
| Server | Uvicorn | ASGI server for FastAPI |
| Testing | pytest | Unit tests |
| Config | python-dotenv | Environment variable management |

---

## 7. How It Works — Pipeline Flow

### Stage 1: Red Engine (Adversary Simulation)

The Red Engine accepts a MITRE ATT&CK technique ID and generates `N` synthetic Windows telemetry logs that mimic what a real attack would produce. No actual malicious code is executed — all output is simulated data.

For `T1059.001` (PowerShell), it generates Event ID 4104 logs with realistic encoded commands and download cradles. For `T1003.001` (LSASS), it generates Sysmon Event ID 10 (process access) logs targeting `lsass.exe` with known tool names like `mimikatz.exe` and `procdump.exe`. All 7 techniques follow the same pattern, each with technique-specific field values drawn from real-world threat intelligence.

### Stage 2: Blue Engine (LLM-Powered Detection)

The Blue Engine takes the top 3 logs from Stage 1 and constructs a structured prompt for the LLM API. The prompt instructs the model to act as a detection engineer and return a valid Sigma YAML rule based on the log indicators.

The engine parses the response, validates the YAML structure, and maps it to a `SigmaRule` Pydantic model. If `DEMO_MODE=true` or no API key is set, the Mock Blue Engine is used instead — it returns hardcoded Sigma rules so the pipeline runs fully offline.

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
- Anthropic API key ([get one here](https://console.anthropic.com/)) — optional if using DEMO_MODE

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
# Open .env and add your ANTHROPIC_API_KEY
```

### .env File

```
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxxxxx
APP_ENV=development
LOG_LEVEL=INFO
RULES_OUTPUT_DIR=rules_output
LOGS_DIR=logs
```

To run without an API key, set `DEMO_MODE=true` in `.env`. The pipeline will use hardcoded Sigma rules via the Mock Blue Engine.

---

## 9. Running the Framework

### Start the API Server

```bash
python main.py
```

Server starts at `http://localhost:8000`

### Access the Dashboard

Open `dashboard.html` in a browser. Ensure the API server is running first.

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
- View the generated Sigma rule with syntax highlighting
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

**Why an LLM for rule generation?**
Writing Sigma rules manually for each technique requires a detection engineer who understands both the attack behaviour and the SIEM field schema. An LLM can be prompted to perform this translation automatically given log samples, removing the human bottleneck in the Blue Team stage of a Purple Team exercise.

**Why simulate logs instead of using real ones?**
Using real attack logs would require executing actual malicious tools in a controlled lab environment, which is outside the scope of this project. Simulation using known IOC patterns from public threat intelligence (Mimikatz signatures, PowerShell cradle patterns) produces logs that are structurally identical to real ones from the perspective of a Sigma rule.

**Why is there a Mock Blue Engine?**
The Mock Blue Engine allows the entire pipeline to run offline without an API key. This is used for academic demonstrations, testing, and environments where live API calls are not available. It is toggled via `DEMO_MODE=true` in the `.env` file.

**Why is `rules_output/` excluded from version control?**
These are generated pipeline artifacts, not source code. Committing them would misrepresent them as static authored rules rather than dynamic output of the pipeline. The directory is created at runtime.

---

## 14. Limitations & Future Work

**Current Limitations:**
- Red Engine generates synthetic logs; it does not interface with real Windows event infrastructure
- Blue Engine sends only 3 sample logs to the LLM due to context window constraints
- Validator models Sigma `contains` behaviour only — does not account for `not` conditions or multi-selection logic
- No authentication on the FastAPI server (development only)

**Planned Extensions:**
- Integrate with Elastic Stack to deploy generated Sigma rules directly into a real SIEM
- Add LLM feedback loop: if Validator returns FAIL, automatically re-prompt with failure context for rule refinement
- Replace synthetic log generation with Atomic Red Team test output via subprocess integration
- Add multi-technique chaining to simulate kill chain sequences
- Add TAXII/STIX export for threat intelligence sharing

---

## 15. Academic References

1. MITRE ATT&CK Framework — https://attack.mitre.org/
2. Sigma Rule Specification — https://github.com/SigmaHQ/sigma
3. Anthropic Claude API Documentation — https://docs.anthropic.com/
4. Pydantic v2 Documentation — https://docs.pydantic.dev/
5. FastAPI Documentation — https://fastapi.tiangolo.com/
6. Sysmon Event ID Reference — https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
7. Windows Security Event Log Reference — https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/
8. Thomas, S. et al. (2023). "Automating Threat Detection with Large Language Models." *IEEE Security & Privacy.*
9. Shin, R. et al. (2024). "LLM-Assisted Detection Rule Generation for SIEM Platforms." *USENIX Security Symposium.*

---

*All attack simulations are synthetic and do not interact with real systems or networks.*
