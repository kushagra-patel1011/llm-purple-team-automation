# app/store/artifact_store.py
# Kushagra Patel | Roll No. 2201302012 | Quantum University Roorkee
# LLM-Driven Purple Team Automation Framework — Artifact Store (Persistence Layer)

from __future__ import annotations
import json
import logging
from datetime import datetime
from pathlib import Path
from app.config import RULES_OUTPUT_DIR, LOGS_DIR
from app.schema.schema import PipelineResult

logger = logging.getLogger(__name__)


# ── JSON Serialiser Helper ────────────────────────────────────────────────────

def _json_serial(obj):
    """Handle datetime and other non-serialisable types."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serialisable")


# ── Artifact Store Class ──────────────────────────────────────────────────────

class ArtifactStore:
    """
    Persistence layer for pipeline results.
    Saves:
      - Full pipeline result as JSON  → logs/
      - Generated Sigma rule as .yml  → rules_output/
    """

    def save(self, result: PipelineResult) -> dict[str, str]:
        """
        Save pipeline artifacts to disk.
        Returns a dict with the paths of saved files.
        """

        pipeline_id  = result.pipeline_id
        technique_id = result.technique_id.replace(".", "_")
        timestamp    = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        saved_paths = {}

        # ── 1. Save Full Pipeline Result as JSON ──────────────────
        json_filename = f"{technique_id}_{timestamp}_{pipeline_id[:8]}.json"
        json_path     = LOGS_DIR / json_filename

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(
                result.model_dump(),
                f,
                indent=2,
                default=_json_serial
            )

        saved_paths["json"] = str(json_path)
        logger.info("Pipeline JSON saved -> %s", json_path)

        # ── 2. Save Sigma Rule as YAML ────────────────────────────
        yml_filename = f"{technique_id}_{timestamp}_{pipeline_id[:8]}.yml"
        yml_path     = RULES_OUTPUT_DIR / yml_filename

        with open(yml_path, "w", encoding="utf-8") as f:
            f.write(result.blue_result.sigma_rule.raw_yaml)

        saved_paths["sigma_rule"] = str(yml_path)
        logger.info("Sigma Rule YAML saved -> %s", yml_path)

        return saved_paths

    def list_runs(self) -> list[dict]:
        """
        List all saved pipeline runs from the logs directory.
        Returns a list of summary dicts sorted by newest first.
        """
        runs = []

        for json_file in sorted(LOGS_DIR.glob("*.json"), reverse=True):
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                runs.append({
                    "pipeline_id":    data.get("pipeline_id", "unknown"),
                    "technique_id":   data.get("technique_id", "unknown"),
                    "overall_status": data.get("overall_status", "unknown"),
                    "coverage_score": data.get("validator_result", {}).get("coverage_score", 0),
                    "completed_at":   data.get("completed_at", "unknown"),
                    "file":           str(json_file),
                })
            except Exception as e:
                logger.warning("Could not read %s: %s", json_file, e)

        return runs

    def load_run(self, pipeline_id: str) -> dict | None:
        """
        Load a specific pipeline run by pipeline_id prefix.
        Returns the full JSON dict or None if not found.
        """
        for json_file in LOGS_DIR.glob("*.json"):
            if pipeline_id in json_file.name:
                with open(json_file, "r", encoding="utf-8") as f:
                    return json.load(f)
        return None


# ── Quick Self-Test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    from app.engines.orchestrator import Orchestrator
    from app.schema.schema import PipelineRequest, TechniqueID

    logger.info("Running self-test...")

    orchestrator = Orchestrator()
    request = PipelineRequest(
        technique_id=TechniqueID.POWERSHELL,
        log_count=3,
        save_artifacts=True,
    )
    result = orchestrator.run(request)

    store = ArtifactStore()
    paths = store.save(result)

    for key, path in paths.items():
        logger.info("Saved %s -> %s", key, path)

    for run in store.list_runs():
        logger.info("[%s] %s — coverage: %.1f%% — id: %s...",
                    run["overall_status"], run["technique_id"],
                    run["coverage_score"] * 100, run["pipeline_id"][:8])