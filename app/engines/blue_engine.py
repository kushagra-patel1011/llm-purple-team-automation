# app/engines/blue_engine.py
# Kushagra Patel | Roll No. 2201302012 | Quantum University Roorkee
# LLM-Driven Purple Team Automation Framework — Blue Engine (Offline Sigma Rule Generation)

from __future__ import annotations
import logging
import uuid
import yaml
from app.schema.schema import TelemetryLog, SigmaRule, BlueEngineResult
from app.engines.mock_blue_engine import _SIGMA_RULES

logger = logging.getLogger(__name__)


# ── Sigma YAML Parser ─────────────────────────────────────────────────────────

def _parse_sigma_yaml(raw_yaml: str, technique_id: str) -> SigmaRule:
    """Parse raw YAML string into a SigmaRule model."""
    try:
        data = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML: {e}\n\nRaw:\n{raw_yaml}")

    return SigmaRule(
        rule_id=str(data.get("id", uuid.uuid4())),
        title=data.get("title", "Unknown Rule"),
        description=data.get("description", ""),
        technique_id=technique_id,
        status=data.get("status", "experimental"),
        level=data.get("level", "high"),
        logsource=data.get("logsource", {}),
        detection=data.get("detection", {}),
        condition=data.get("detection", {}).get("condition", ""),
        raw_yaml=raw_yaml,
    )


# ── Blue Engine Class ─────────────────────────────────────────────────────────

class BlueEngine:
    """
    Detection generation engine — fully offline, no API required.
    Returns pre-written Sigma rules from a hardcoded dictionary keyed by
    MITRE ATT&CK technique ID.  The rule set lives in mock_blue_engine._SIGMA_RULES
    so there is a single source of truth for all supported techniques.
    """

    def run(self, technique_id: str, logs: list[TelemetryLog]) -> BlueEngineResult:

        raw_yaml = _SIGMA_RULES.get(technique_id)

        if raw_yaml is None:
            raw_yaml = (
                f"title: Generic Detection Rule for {technique_id}\n"
                f"id: {uuid.uuid4()}\n"
                f"description: Placeholder rule — no rule defined for {technique_id}\n"
                f"status: experimental\nlevel: medium\n"
                f"logsource:\n  product: windows\ndetection:\n  condition: none\n"
                f"tags:\n  - attack.{technique_id.lower().replace('.', '_')}\n"
            )
            logger.warning("No Sigma rule defined for %s — using placeholder.", technique_id)

        sigma_rule = _parse_sigma_yaml(raw_yaml, technique_id)

        logger.info("[BlueEngine] Sigma rule for %s: '%s'", technique_id, sigma_rule.title)

        return BlueEngineResult(
            technique_id=technique_id,
            sigma_rule=sigma_rule,
            prompt_tokens=0,
            completion_tokens=0,
        )


# ── Quick Self-Test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    from app.engines.red_engine import RedEngine
    from app.schema.schema import TechniqueID

    red = RedEngine()
    red_result = red.run(TechniqueID.POWERSHELL, log_count=3)

    blue = BlueEngine()
    blue_result = blue.run(
        technique_id=red_result.technique_id,
        logs=red_result.logs,
    )

    logger.info("Rule Title : %s", blue_result.sigma_rule.title)
    logger.info("Technique  : %s", blue_result.sigma_rule.technique_id)
    logger.info("Level      : %s", blue_result.sigma_rule.level)
    logger.info("Generated Sigma Rule:\n%s", blue_result.sigma_rule.raw_yaml)
