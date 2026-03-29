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
# The framework runs fully offline — no API key required.
DEMO_MODE: bool = True

# ── MITRE ATT&CK Techniques Supported ────────────────────────
SUPPORTED_TECHNIQUES: list[str] = [
    "T1059.001",   # PowerShell
    "T1003.001",   # LSASS Memory Dump
    "T1547.001",   # Registry Run Keys / Startup Folder
    "T1055.001",   # DLL Injection (Process Injection)
    "T1078",       # Valid Accounts (Stolen Credential Logon)
    "T1082",       # System Information Discovery
    "T1071.001",   # Application Layer Protocol: Web Protocols (C2 over HTTP/S)
]

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