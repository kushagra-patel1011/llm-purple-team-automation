# app/engines/orchestrator.py
# Kushagra Patel | Roll No. 2201302012 | Quantum University Roorkee
# LLM-Driven Purple Team Automation Framework — Orchestrator (Pipeline Controller)

from __future__ import annotations
import logging
import time
from datetime import datetime
from app.schema.schema import (
    TechniqueID, PipelineRequest, PipelineResult, CoverageStatus
)
from app.engines.red_engine import RedEngine
from app.engines.blue_engine import BlueEngine
from app.engines.validator import ValidatorEngine
from app.store.artifact_store import ArtifactStore

logger = logging.getLogger(__name__)


# ── Orchestrator Class ────────────────────────────────────────────────────────

class Orchestrator:
    """
    Master pipeline controller.
    Accepts a PipelineRequest, runs Red → Blue → Validate in sequence,
    and returns a complete PipelineResult.
    """

    def __init__(self):
        self.red_engine  = RedEngine()
        self.validator   = ValidatorEngine()
        self.store       = ArtifactStore()

        self.blue_engine = BlueEngine()
        logger.info("Blue Engine: BlueEngine (offline/hardcoded rules)")

    def run(self, request: PipelineRequest) -> PipelineResult:
        """
        Execute the full Purple Team pipeline.

        Flow:
          1. Red Engine  — simulate attack, generate telemetry logs
          2. Blue Engine — call Claude API, generate Sigma detection rule
          3. Validator   — score the rule against the logs
          4. Return      — full PipelineResult with all outputs
        """

        technique_id = request.technique_id
        log_count    = request.log_count

        logger.info("Starting pipeline for %s (log_count=%d)", technique_id, log_count)

        # ── Stage 1: Red Engine ───────────────────────────────────
        logger.info("[1/3] Red Engine — simulating %s", technique_id)
        t0 = time.time()

        red_result = self.red_engine.run(
            technique_id=TechniqueID(technique_id),
            log_count=log_count,
        )

        logger.info("[1/3] Done — %d logs generated (%.2fs)",
                    red_result.log_count, time.time() - t0)

        # ── Stage 2: Blue Engine ──────────────────────────────────
        logger.info("[2/3] Blue Engine — generating Sigma rule")
        t1 = time.time()

        blue_result = self.blue_engine.run(
            technique_id=technique_id,
            logs=red_result.logs,
        )

        logger.info("[2/3] Done — rule: '%s' (%.2fs)",
                    blue_result.sigma_rule.title, time.time() - t1)

        # ── Stage 3: Validator ────────────────────────────────────
        logger.info("[3/3] Validator — scoring detection coverage")
        t2 = time.time()

        validator_result = self.validator.run(
            technique_id=technique_id,
            logs=red_result.logs,
            sigma_rule=blue_result.sigma_rule,
        )

        logger.info("[3/3] Done — coverage: %.1f%% [%s] (%.2fs)",
                    validator_result.coverage_score * 100,
                    validator_result.status,
                    time.time() - t2)

        # ── Determine Overall Status ──────────────────────────────
        overall_status = validator_result.status

        # ── Build Final Result ────────────────────────────────────
        pipeline_result = PipelineResult(
            technique_id=technique_id,
            red_result=red_result,
            blue_result=blue_result,
            validator_result=validator_result,
            overall_status=overall_status,
        )

        logger.info("Pipeline complete — ID: %s  status: %s",
                    pipeline_result.pipeline_id, overall_status)

        if request.save_artifacts:
            self.store.save(pipeline_result)

        return pipeline_result


# ── Quick Self-Test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    from app.schema.schema import PipelineRequest, TechniqueID

    # Test all 3 techniques
    techniques = [
        TechniqueID.POWERSHELL,
        TechniqueID.LSASS_DUMP,
        TechniqueID.REGISTRY_PERSIST,
    ]

    orchestrator = Orchestrator()

    for technique in techniques:
        request = PipelineRequest(
            technique_id=technique,
            log_count=5,
            save_artifacts=False,
        )

        result = orchestrator.run(request)

        logger.info(
            "SUMMARY — %s | pipeline=%s | logs=%d | rule='%s' | coverage=%.1f%% | status=%s",
            technique,
            result.pipeline_id,
            result.red_result.log_count,
            result.blue_result.sigma_rule.title,
            result.validator_result.coverage_score * 100,
            result.overall_status,
        )