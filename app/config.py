# app/config.py
# Kushagra Patel | Roll No. 2201302012 | Quantum University Roorkee
# LLM-Driven Purple Team Automation Framework — Configuration Module

import logging
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root
load_dotenv()

# ── Base Paths ────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
RULES_OUTPUT_DIR = BASE_DIR / os.getenv("RULES_OUTPUT_DIR", "rules_output")
LOGS_DIR = BASE_DIR / os.getenv("LOGS_DIR", "logs")

# Create directories if they don't exist
RULES_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# ── App Settings ──────────────────────────────────────────────
APP_ENV: str = os.getenv("APP_ENV", "development")
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

# ── Offline Mode ─────────────────────────────────────────────
# Set DEMO_MODE=true in .env to run without an Anthropic API key.
DEMO_MODE: bool = os.getenv("DEMO_MODE", "true").lower() == "true"

# ── MITRE ATT&CK Techniques — single source of truth ─────────
# Both SUPPORTED_TECHNIQUES (health check / validator) and the
# /techniques endpoint are derived from this one dict, so adding
# a new technique here automatically updates everything.
TECHNIQUE_DETAILS: dict = {
    "T1059.001": {"name": "PowerShell Execution",                      "tactic": "Execution"},
    "T1003.001": {"name": "LSASS Memory Dump",                         "tactic": "Credential Access"},
    "T1547.001": {"name": "Registry Run Key Persistence",              "tactic": "Persistence"},
    "T1055.001": {"name": "DLL Injection",                             "tactic": "Defense Evasion / Privilege Escalation"},
    "T1078":     {"name": "Valid Accounts",                            "tactic": "Persistence / Initial Access"},
    "T1082":     {"name": "System Information Discovery",              "tactic": "Discovery"},
    "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control"},
}

SUPPORTED_TECHNIQUES: list[str] = list(TECHNIQUE_DETAILS.keys())

# ── Scoring Thresholds ────────────────────────────────────────
COVERAGE_THRESHOLD_PASS: float = 0.75   # >= 75% = PASS
COVERAGE_THRESHOLD_WARN: float = 0.50   # 50–74% = WARN
                                         # < 50%  = FAIL

# ── Logging Setup ─────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ── Startup Log ──────────────────────────────────────────────
_log = logging.getLogger(__name__)
_log.info("[CONFIG] Running fully offline — no API key required.")

if __name__ == "__main__":
    _log.info("Loaded successfully.")
    _log.info("Demo Mode   : %s", DEMO_MODE)
    _log.info("Environment : %s", APP_ENV)
    _log.info("Rules Dir   : %s", RULES_OUTPUT_DIR)
    _log.info("Logs Dir    : %s", LOGS_DIR)
    _log.info("Techniques  : %s", SUPPORTED_TECHNIQUES)