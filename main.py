# main.py
# Kushagra Patel | Roll No. 2201302012 | Quantum University Roorkee
# LLM-Driven Purple Team Automation Framework — FastAPI Server

from __future__ import annotations
import logging
import re
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from app.schema.schema import (
    PipelineRequest, PipelineResult, TechniqueID
)
from app.engines.orchestrator import Orchestrator
from app.store.artifact_store import ArtifactStore
from app.config import SUPPORTED_TECHNIQUES, TECHNIQUE_DETAILS, APP_ENV

logger = logging.getLogger(__name__)

_PIPELINE_ID_RE = re.compile(r'^[a-zA-Z0-9-]+$')


# ── App Init ──────────────────────────────────────────────────────────────────

app = FastAPI(
    title="LLM-Driven Purple Team Automation Framework",
    description="Automates Red→Blue→Validate pipeline using MITRE ATT&CK + Claude AI",
    version="1.0.0",
    contact={
        "name": "Kushagra Patel",
        "email": "kushagra@quantumuniversity.edu.in",
    }
)

# ── CORS — Allow React Dashboard to Call This API ─────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,  # Must be False when allow_origins=["*"] — browser will block otherwise
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Engine & Store Instances ──────────────────────────────────────────────────

orchestrator = Orchestrator()
store        = ArtifactStore()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
def root():
    """Health check — confirms server is running."""
    return {
        "status": "online",
        "project": "LLM-Driven Purple Team Automation Framework",
        "author": "Kushagra Patel | Roll No. 2201302012",
        "university": "Quantum University Roorkee",
        "version": "1.0.0",
        "environment": APP_ENV,
    }


@app.get("/health", tags=["Health"])
def health():
    """Detailed health check."""
    return {
        "status": "healthy",
        "supported_techniques": SUPPORTED_TECHNIQUES,
    }


@app.get("/techniques", tags=["Techniques"])
def list_techniques():
    """List all supported MITRE ATT&CK techniques."""
    # Built dynamically from TECHNIQUE_DETAILS in config.py — no manual sync needed.
    return {
        "techniques": [
            {"id": tid, "name": details["name"], "tactic": details["tactic"]}
            for tid, details in TECHNIQUE_DETAILS.items()
        ]
    }


@app.post("/pipeline/run", response_model=PipelineResult, tags=["Pipeline"])
def run_pipeline(request: PipelineRequest):
    """
    Trigger the full Purple Team pipeline.

    - **technique_id**: MITRE ATT&CK technique (T1059.001 / T1003.001 / T1547.001)
    - **log_count**: Number of telemetry logs to simulate (1–50)
    - **save_artifacts**: Whether to save results to disk
    """
    try:
        result = orchestrator.run(request)
        return result

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline error: {str(e)}")


@app.get("/runs", tags=["History"])
def list_runs(
    limit: int = Query(default=20, ge=1, le=100, description="Max results to return"),
    offset: int = Query(default=0, ge=0, description="Number of results to skip"),
):
    """List previously saved pipeline runs with pagination."""
    try:
        all_runs = store.list_runs()
        total = len(all_runs)
        page = all_runs[offset : offset + limit]
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "runs": page,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/runs/{pipeline_id}", tags=["History"])
def get_run(pipeline_id: str):
    """Retrieve a specific pipeline run by pipeline ID."""
    if not _PIPELINE_ID_RE.match(pipeline_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid pipeline_id format. Only alphanumeric characters and hyphens are allowed.",
        )
    result = store.load_run(pipeline_id)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=f"Pipeline run '{pipeline_id}' not found."
        )
    return result


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )