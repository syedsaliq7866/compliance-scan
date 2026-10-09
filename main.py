"""
ComplianceScan AI Security API (Local Llama 3, Agentic) - SANDBOX BUILD
Autonomous Cloud Security Agent with Local Free AI & Human-in-the-Loop Safeguards

This version replaces the earlier single-shot "send findings, get back one
JSON decision" classifier with a real agent (agent_graph.py, built on
LangGraph): the model is given the scanners themselves as tools, decides
which to call and when it's done investigating, and -- after a human
approves a fix -- a second small graph re-checks the resource to confirm
the fix actually worked. See agent_graph.py's module docstring for the full
design rationale, including why it still falls back to the old deterministic
rule-based behavior if the local model's tool-calling loop fails.

Unchanged from before:
- Typed Pydantic models validate everything crossing a boundary.
- Every AWS call that can fail falls back to deterministic mock data instead
  of crashing the demo.
- ALLOWED_ACTIONS whitelist still gates every execution; nothing the agent
  proposes can run outside it.
- enable_mfa / deactivate_key still mean what quarantine_user_pending_mfa /
  deactivate_stale_key say (see remediation.py).
- Optional API key header (set API_KEY env var to turn on).
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel

import agent_graph
import remediation

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("compliance-scan")

app = FastAPI(
    title="ComplianceScan AI Security API (Local Llama 3, Agentic)",
    description="Autonomous Cloud Security Agent with Local Free AI & Human-in-the-Loop Safeguards",
)

import os
API_KEY = os.getenv("API_KEY")  # if unset, auth is skipped (demo-friendly default)

# In-memory store for pending approvals (unchanged from before -- a demo-scale
# store is fine here; see README for the production note on this).
pending_actions = {}


class ActionApproval(BaseModel):
    action_id: str


def require_api_key(x_api_key: Optional[str] = Header(default=None)):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header.")
    return True


@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


@app.post("/api/scan", dependencies=[Depends(require_api_key)])
def trigger_security_scan():
    """
    Runs the agentic investigation (agent_graph.run_scan()):
    1. The agent decides which of IAM/S3/monitoring to check and calls those
       scanner tools itself (or, if the local model's tool-calling fails,
       falls back to the same fixed-order scan + rule-based mapping the
       pre-agentic version used -- see agent_graph.py).
    2. For each real finding, the agent stages a remediation with its own
       reasoning text, tagged with which path produced it (`decided_by`:
       "llama3_agentic" or "rule_fallback").
    3. Writes findings + decisions to compliance_report.json.
    4. Stages actions for human approval -- nothing here touches AWS.
    """
    try:
        result = agent_graph.run_scan()
        findings = result.get("findings", [])
        staged = result.get("staged_actions", [])

        if not findings:
            report_data = {"status": "SECURE", "findings": [], "ai_analysis": "No vulnerabilities detected."}
            with open("compliance_report.json", "w") as f:
                json.dump(report_data, f, indent=2)
            return {"message": "All resources are secure.", "report": report_data}

        for entry in staged:
            pending_actions[entry["action_id"]] = entry

        report_data = {
            "status": "VULNERABILITIES_FOUND",
            "raw_findings": findings,
            "ai_analysis": result.get("analysis_summary", ""),
            "decided_by": result.get("decided_by", "unknown"),
            "tool_calls": result.get("tool_calls_log", []),
            "pending_actions": staged,
        }
        with open("compliance_report.json", "w") as f:
            json.dump(report_data, f, indent=2)

        return {
            "message": "Scan complete. Fixes staged in compliance_report.json.",
            "ai_summary": result.get("analysis_summary", ""),
            "decided_by": result.get("decided_by", "unknown"),
            "tool_calls": result.get("tool_calls_log", []),
            "pending_actions": staged,
        }

    except Exception as e:
        log.exception("Scan failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/pending", dependencies=[Depends(require_api_key)])
def view_pending_actions():
    """Lists all agent-proposed fixes awaiting approval."""
    return {"pending_actions": list(pending_actions.values())}


@app.post("/api/approve", dependencies=[Depends(require_api_key)])
def approve_and_execute(approval: ActionApproval):
    """
    Executes a staged fix on AWS after human confirmation, then re-checks the
    resource to confirm the fix actually worked (agent_graph.run_remediation(),
    the remediate -> verify graph). Falls back to a dry-run message (no AWS
    call, no verification) if credentials aren't available, so this still
    demos cleanly without live AWS access.
    """
    if approval.action_id not in pending_actions:
        raise HTTPException(status_code=404, detail="Action ID not found.")

    task = pending_actions[approval.action_id]

    if task["status"] != "PENDING_APPROVAL":
        raise HTTPException(status_code=400, detail=f"Action is already {task['status']}.")

    if task["action"] not in remediation.ALLOWED_ACTIONS:
        raise HTTPException(status_code=403, detail=f"Action '{task['action']}' is blocked by guardrails.")

    try:
        result = agent_graph.run_remediation(task)
        task["status"] = result["status"]
        task["verification_status"] = result.get("verification_status", "UNKNOWN")

        try:
            with open("compliance_report.json", "r") as f:
                current_report = json.load(f)
            current_report["latest_remediation"] = task
            with open("compliance_report.json", "w") as f:
                json.dump(current_report, f, indent=2)
        except FileNotFoundError:
            pass

        return {
            "status": "SUCCESS",
            "message": result["message"],
            "verification_status": task["verification_status"],
        }

    except HTTPException:
        raise
    except Exception as e:
        log.exception("Remediation failed")
        raise HTTPException(status_code=500, detail=f"Execution error: {str(e)}")
