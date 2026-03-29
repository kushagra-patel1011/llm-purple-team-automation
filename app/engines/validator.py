# app/engines/validator.py
# Kushagra Patel | Roll No. 2201302012 | Quantum University Roorkee
# LLM-Driven Purple Team Automation Framework — Validator Engine (Coverage Scoring)

from __future__ import annotations
import logging
import re
from app.config import COVERAGE_THRESHOLD_PASS, COVERAGE_THRESHOLD_WARN
from app.schema.schema import (
    TelemetryLog, SigmaRule, ValidatorResult, ValidationDetail, CoverageStatus
)

logger = logging.getLogger(__name__)


# ── Keyword Extractor ─────────────────────────────────────────────────────────

def _extract_keywords(sigma_rule: SigmaRule) -> list[str]:
    """
    Pull all string indicators from the Sigma rule's detection block.
    Handles contains, endswith, startswith, and plain string values.
    """
    keywords = []

    def _recurse(obj):
        if isinstance(obj, str):
            stripped = obj.strip().lower()
            if len(stripped) > 2:  # ignore tiny strings
                keywords.append(stripped)
        elif isinstance(obj, list):
            for item in obj:
                _recurse(item)
        elif isinstance(obj, dict):
            for k, v in obj.items():
                if k.lower() != "condition":  # skip condition key
                    _recurse(v)

    _recurse(sigma_rule.detection)
    return list(set(keywords))  # deduplicate


# ── Log Matcher ───────────────────────────────────────────────────────────────

def _match_log(log: TelemetryLog, keywords: list[str]) -> tuple[bool, str]:
    """
    Realistic Sigma matching — only checks fields that Sigma rules
    actually target in a real SIEM. Does NOT search the entire raw log.
    """

    # Only search these specific, realistic fields
    targeted_fields = {
        "command_line":     (log.command_line  or "").lower(),
        "process_name":     (log.process_name  or "").lower(),
        "parent_process":   (log.parent_process or "").lower(),
        "registry_key":     (log.registry_key  or "").lower(),
        "event_id":         str(log.event_id),
        # T1078 (Valid Accounts) — indicators live in raw_log
        "username":         (log.username or "").lower(),
        "ip_address":       str(log.raw_log.get("IpAddress", "")).lower(),
        "logon_type":       str(log.raw_log.get("LogonType", "")).lower(),
        "auth_package":     str(log.raw_log.get("AuthPackage", "")).lower(),
        # T1082 (System Info Discovery) — Image field in raw_log
        "image":            str(log.raw_log.get("Image", "")).lower(),
        # T1071.001 (Web Protocol C2) — network connection fields
        "destination_ip":   str(log.raw_log.get("DestinationIp", "")).lower(),
        "destination_port": str(log.raw_log.get("DestinationPort", "")),
        "initiated":        str(log.raw_log.get("Initiated", "")).lower(),
        # T1003.001 (LSASS) — Sysmon Event 10 fields
        "target_process":   str(log.raw_log.get("TargetProcessName", "")).lower(),
        "granted_access":   str(log.raw_log.get("GrantedAccess", "")).lower(),
    }

    for keyword in keywords:
        kw = keyword.strip().lower()
        if len(kw) < 3:
            continue

        # Skip pure numeric strings that are too generic (e.g. "1")
        if kw.isdigit() and len(kw) < 4:
            continue

        for field_name, field_value in targeted_fields.items():
            if kw in field_value:
                return True, f"Matched '{kw}' in {field_name}"

    return False, "No Sigma field match found"


# ── Validator Engine Class ────────────────────────────────────────────────────

class ValidatorEngine:
    """
    Coverage validation engine.
    Checks how many telemetry logs the generated Sigma rule would detect.
    Returns a ValidatorResult with coverage score and PASS/WARN/FAIL status.
    """

    def run(
        self,
        technique_id: str,
        logs: list[TelemetryLog],
        sigma_rule: SigmaRule,
    ) -> ValidatorResult:

        # 1. Extract keywords from Sigma rule
        keywords = _extract_keywords(sigma_rule)

        # 2. Match each log against keywords
        details = []
        matched_count = 0

        for log in logs:
            matched, reason = _match_log(log, keywords)
            if matched:
                matched_count += 1
            details.append(ValidationDetail(
                log_id=log.log_id,
                matched=matched,
                match_reason=reason,
            ))

        # 3. Compute coverage score
        total = len(logs)
        score = round(matched_count / total, 4) if total > 0 else 0.0

        # 4. Determine status
        if score >= COVERAGE_THRESHOLD_PASS:
            status = CoverageStatus.PASS
        elif score >= COVERAGE_THRESHOLD_WARN:
            status = CoverageStatus.WARN
        else:
            status = CoverageStatus.FAIL

        # 5. Return result
        return ValidatorResult(
            technique_id=technique_id,
            total_logs=total,
            matched_logs=matched_count,
            coverage_score=score,
            status=status,
            details=details,
        )


# ── Quick Self-Test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    from app.engines.red_engine import RedEngine
    from app.engines.blue_engine import BlueEngine
    from app.schema.schema import TechniqueID

    logger.info("Running full pipeline test: Red -> Blue -> Validate")

    red = RedEngine()
    red_result = red.run(TechniqueID.POWERSHELL, log_count=5)
    logger.info("[Red]  Generated %d logs for %s", red_result.log_count, red_result.technique_id)

    blue = BlueEngine()
    blue_result = blue.run(
        technique_id=red_result.technique_id,
        logs=red_result.logs
    )
    logger.info("[Blue] Rule generated: '%s'", blue_result.sigma_rule.title)

    validator = ValidatorEngine()
    val_result = validator.run(
        technique_id=red_result.technique_id,
        logs=red_result.logs,
        sigma_rule=blue_result.sigma_rule,
    )

    logger.info("Coverage: %.1f%% | matched: %d/%d | status: %s",
                val_result.coverage_score * 100,
                val_result.matched_logs,
                val_result.total_logs,
                val_result.status)
    for d in val_result.details:
        logger.info("  log %s... matched=%s reason=%s", d.log_id[:8], d.matched, d.match_reason)