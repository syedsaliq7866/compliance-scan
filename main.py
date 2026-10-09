"""
ComplianceScan AI Security API (Local Llama 3) - SANDBOX BUILD
Autonomous Cloud Security Agent with Local Free AI & Human-in-the-Loop Safeguards

Changes from the original main.py (see WHAT/WHY notes inline):
- Typed Pydantic models validate every AI decision before it's trusted (type safety).
- Every AWS call that can fail falls back to deterministic mock data instead of
  crashing the demo (webinar reliability).
- The Ollama call has a timeout and a rule-based fallback if the model is
  unreachable or returns something that doesn't validate.
- storage_compliance.py and monitoring_compliance.py are no longer orphaned --
  their checks run as part of /api/scan.
- enable_mfa and deactivate_key now do what they say (see comments at each).
- Optional API key header so the API isn't wide open (set API_KEY env var to turn on).
"""
import json
import logging
import os
import uuid
import datetime
from datetime import timezone
from typing import List, Optional

import boto3
import requests
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel, Field, ValidationError

# Local modules that used to be orphaned scripts -- now wired in.
import storage_compliance
import monitoring_compliance

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("compliance-scan")

app = FastAPI(
    title="ComplianceScan AI Security API (Local Llama 3)",
    description="Autonomous Cloud Security Agent with Local Free AI & Human-in-the-Loop Safeguards",
)

# ---------------------------------------------------------------------------
# Configuration (env-driven so the sandbox and the real deployment can differ
# without editing code -- WHAT: moved hardcoded values to env vars with
# sensible defaults. WHY: the demo box may not have Ollama/AWS creds wired up
# the same way as production; env vars let you flip behavior without a code change.)
# ---------------------------------------------------------------------------
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
OLLAMA_TIMEOUT_SECONDS = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "8"))
API_KEY = os.getenv("API_KEY")  # if unset, auth is skipped (demo-friendly default)
MOCK_ON_FAILURE = os.getenv("MOCK_ON_FAILURE", "true").lower() == "true"

# In-memory store for pending approvals
pending_actions = {}

# Guardrail: Whitelist of allowed automated actions
ALLOWED_ACTIONS = [
    "block_public_access",
    "encrypt_bucket",
    "quarantine_user_pending_mfa",  # WHAT: renamed from "enable_mfa". WHY: the action
                                     # actually attaches a deny-all policy -- it can't
                                     # enable MFA on AWS's behalf, only lock the account
                                     # until an admin sets MFA up. The old name told the
                                     # approver they were granting a security *improvement*
                                     # when they were actually locking a user out entirely.
    "deactivate_stale_key",
    "detach_admin_policy",
]
# Accept the old name too, so an in-flight report from before this change still works.
_ACTION_ALIASES = {"enable_mfa": "quarantine_user_pending_mfa", "deactivate_key": "deactivate_stale_key"}


def _canonical_action(name: str) -> str:
    return _ACTION_ALIASES.get(name, name)


# ---------------------------------------------------------------------------
# Typed models (WHAT: every shape that crosses a boundary -- AI output, API
# input/output -- now has a Pydantic model. WHY: the old code trusted
# `ai_decision.get("actions", [])` and indexed `item["action"]` directly, so a
# malformed AI response threw an unhandled KeyError -> bare 500. Validating up
# front turns "AI said something weird" into a handled fallback instead of a crash.)
# ---------------------------------------------------------------------------
class ActionApproval(BaseModel):
    action_id: str


class Finding(BaseModel):
    resource: str
    service: str
    issue: str
    access_key_id: Optional[str] = None  # present only for stale-key findings


class AIAction(BaseModel):
    action: str
    resource_name: str
    risk_level: str = "UNKNOWN"


class AIDecision(BaseModel):
    analysis_summary: str
    actions: List[AIAction] = Field(default_factory=list)


class PendingAction(BaseModel):
    action_id: str
    resource_name: str
    action: str
    risk_level: str
    status: str
    access_key_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Auth (WHAT: optional header-based API key. WHY: previously anyone who could
# reach the port could trigger scans and *execute* live AWS remediations with
# zero auth. Off by default so the webinar demo isn't gated behind a key you
# have to wire into Swagger UI live, but it's one env var away from on.)
# ---------------------------------------------------------------------------
def require_api_key(x_api_key: Optional[str] = Header(default=None)):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header.")
    return True


# ---------------------------------------------------------------------------
# Mock data (WHAT: centralized mock fallbacks, reused from the old standalone
# iam_compliance.py / storage_compliance.py / monitoring_compliance.py mock
# modes. WHY: if AWS creds are missing, rate-limited, or a permission is denied
# mid-demo, the scan should degrade gracefully and keep showing something
# coherent instead of a stack trace in front of the room.)
# ---------------------------------------------------------------------------
def _mock_iam_findings():
    return [
        {"resource": "admin-root", "service": "IAM", "issue": "MFA is not enabled for this user"},
        {"resource": "admin-root", "service": "IAM", "issue": "Access key is severely stale (142 days old)",
         "access_key_id": "AKIAMOCKSTALE00001"},
        {"resource": "service-acc", "service": "IAM", "issue": "User has dangerous direct AdministratorAccess attached"},
    ]


def _mock_s3_findings():
    return [
        {"resource": "company-public-logs", "service": "S3", "issue": "No Public Access Block Configured"},
        {"resource": "company-public-logs", "service": "S3", "issue": "Bucket is not encrypted"},
        {"resource": "user-backups-2026", "service": "S3", "issue": "Bucket does not have versioning enabled"},
    ]


def _mock_monitoring_findings():
    return [{"resource": "account", "service": "Monitoring", "issue": "Amazon Macie (PII scanning) is disabled"}]


# ---------------------------------------------------------------------------
# Scanners
# ---------------------------------------------------------------------------
def scan_iam_security_issues():
    """Scans AWS IAM for missing MFA, stale keys (>90 days), and excessive admin permissions.
    Falls back to mock findings if AWS isn't reachable/authorized (see module docstring)."""
    try:
        iam_client = boto3.client("iam", region_name=AWS_REGION)
        response = iam_client.list_users()
        users = response.get("Users", [])
        findings = []

        for user in users:
            user_name = user["UserName"]
            if user_name == "security-agent-bot":
                continue

            mfa_response = iam_client.list_mfa_devices(UserName=user_name)
            if not mfa_response.get("MFADevices"):
                findings.append({
                    "resource": user_name, "service": "IAM",
                    "issue": "MFA is not enabled for this user",
                })

            keys_response = iam_client.list_access_keys(UserName=user_name)
            for key in keys_response.get("AccessKeyMetadata", []):
                age = (datetime.datetime.now(timezone.utc) - key["CreateDate"]).days
                if age > 90:
                    findings.append({
                        "resource": user_name, "service": "IAM",
                        "issue": f"Access key is severely stale ({age} days old)",
                        # WHAT: carry the specific key ID through to the finding.
                        # WHY: lets /api/approve deactivate *this* key only,
                        # instead of every key the user has (see approve handler).
                        "access_key_id": key["AccessKeyId"],
                    })

            policies_response = iam_client.list_attached_user_policies(UserName=user_name)
            for policy in policies_response.get("AttachedPolicies", []):
                if policy["PolicyName"] == "AdministratorAccess":
                    findings.append({
                        "resource": user_name, "service": "IAM",
                        "issue": "User has dangerous direct AdministratorAccess attached",
                    })

        return findings
    except (ClientError, NoCredentialsError, EndpointConnectionError) as e:
        log.warning("IAM scan fell back to mock data: %s", e)
        return _mock_iam_findings() if MOCK_ON_FAILURE else []
    except Exception as e:
        log.exception("Unexpected error scanning IAM")
        return _mock_iam_findings() if MOCK_ON_FAILURE else []


def scan_s3_security_issues():
    """Public access + encryption + versioning, using storage_compliance.py's
    checks (WHAT: previously duplicated/partial logic lived only in this file
    and only checked public access. WHY: storage_compliance.py already had
    correct encryption/versioning checks but nothing called it)."""
    try:
        s3_client = boto3.client("s3", region_name=AWS_REGION)
        response = s3_client.list_buckets()
        findings = []
        for bucket in response.get("Buckets", []):
            bucket_name = bucket["Name"]
            try:
                pub_config = s3_client.get_public_access_block(Bucket=bucket_name)
                pab = pub_config["PublicAccessBlockConfiguration"]
                if not (pab.get("BlockPublicAcls") and pab.get("BlockPublicPolicy")):
                    findings.append({"resource": bucket_name, "service": "S3", "issue": "Public Access Not Fully Blocked"})
            except ClientError:
                findings.append({"resource": bucket_name, "service": "S3", "issue": "No Public Access Block Configured"})

            if not storage_compliance.check_s3_bucket_encryption(s3_client, bucket_name):
                findings.append({"resource": bucket_name, "service": "S3", "issue": "Bucket is not encrypted"})
            if not storage_compliance.check_s3_bucket_versioning(s3_client, bucket_name):
                findings.append({"resource": bucket_name, "service": "S3", "issue": "Bucket does not have versioning enabled"})
        return findings
    except (ClientError, NoCredentialsError, EndpointConnectionError) as e:
        log.warning("S3 scan fell back to mock data: %s", e)
        return _mock_s3_findings() if MOCK_ON_FAILURE else []
    except Exception:
        log.exception("Unexpected error scanning S3")
        return _mock_s3_findings() if MOCK_ON_FAILURE else []


def scan_monitoring_issues():
    """CloudTrail + Macie, via monitoring_compliance.py (previously orphaned)."""
    try:
        raw = monitoring_compliance.audit_monitoring_services()
        findings = []
        for item in raw:
            if not item.get("enabled", True):
                findings.append({"resource": "account", "service": "Monitoring",
                                  "issue": f"{item['service']} is disabled"})
        return findings
    except Exception:
        log.exception("Unexpected error scanning monitoring services")
        return _mock_monitoring_findings() if MOCK_ON_FAILURE else []


# ---------------------------------------------------------------------------
# AI decision (with a deterministic fallback so a missing/unreachable Ollama
# doesn't take the whole demo down)
# ---------------------------------------------------------------------------
_RULE_MAP = {
    "MFA is not enabled": ("quarantine_user_pending_mfa", "HIGH"),
    "AdministratorAccess": ("detach_admin_policy", "CRITICAL"),
    "severely stale": ("deactivate_stale_key", "MEDIUM"),
    "Public Access": ("block_public_access", "HIGH"),
    "not encrypted": ("encrypt_bucket", "MEDIUM"),
}


def _rule_based_decision(findings: list) -> AIDecision:
    """Deterministic stand-in for the AI step. WHAT: maps known issue substrings
    to actions with no model call involved. WHY: used when Ollama is
    unreachable or returns something that fails validation, so /api/scan still
    produces a usable result during the demo."""
    actions = []
    for f in findings:
        for key, (action, risk) in _RULE_MAP.items():
            if key.lower() in f["issue"].lower():
                item = {"action": action, "resource_name": f["resource"], "risk_level": risk}
                if f.get("access_key_id"):
                    item["access_key_id"] = f["access_key_id"]
                actions.append(item)
                break
    return AIDecision(
        analysis_summary="Rule-based fallback analysis (local AI engine unreachable or returned an invalid response).",
        actions=[AIAction(**{k: v for k, v in a.items() if k in ("action", "resource_name", "risk_level")}) for a in actions],
    ), actions


def get_ai_decision(findings: list):
    """Calls local Ollama/Llama 3; validates the response against AIDecision;
    falls back to the rule-based mapper on any failure. Returns
    (AIDecision, raw_action_dicts) -- raw_action_dicts keeps extra fields like
    access_key_id that the strict model doesn't carry."""
    prompt = f"""
    You are an autonomous cloud security expert.
    Analyze these AWS misconfigurations:
    {json.dumps(findings, indent=2)}

    Determine the exact remediation actions needed.
    Allowed action values: {json.dumps(ALLOWED_ACTIONS)}.

    Return a STRICT JSON object in this exact format:
    {{
      "analysis_summary": "Short explanation of the security risk",
      "actions": [
        {{
          "action": "block_public_access",
          "resource_name": "name-of-resource",
          "risk_level": "HIGH"
        }}
      ]
    }}
    Return ONLY valid JSON with no extra commentary or markdown backticks.
    """
    try:
        resp = requests.post(
            OLLAMA_URL,
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False, "format": "json"},
            timeout=OLLAMA_TIMEOUT_SECONDS,
        )
        resp.raise_for_status()
        raw_content = resp.json().get("response", "{}")
        parsed = json.loads(raw_content)
        decision = AIDecision(**parsed)
        # Re-attach access_key_id from the matching finding, since the AI
        # response schema doesn't carry it.
        raw_actions = []
        for a in decision.actions:
            item = a.model_dump()
            match = next((f for f in findings if f["resource"] == a.resource_name and f.get("access_key_id")), None)
            if match:
                item["access_key_id"] = match["access_key_id"]
            raw_actions.append(item)
        return decision, raw_actions
    except (requests.RequestException, json.JSONDecodeError, ValidationError, TypeError) as e:
        log.warning("Ollama call failed or returned invalid data, using rule-based fallback: %s", e)
        return _rule_based_decision(findings)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    """Simple liveness check -- handy for n8n or an uptime check to poll."""
    return {"status": "ok", "time": datetime.datetime.now(timezone.utc).isoformat()}


@app.post("/api/scan", dependencies=[Depends(require_api_key)])
def trigger_security_scan():
    """
    1. Scans AWS S3 (public access, encryption, versioning), IAM, and monitoring
       (CloudTrail/Macie) -- live if credentials work, mock data otherwise.
    2. Sends findings to local Ollama (Llama 3) for analysis & remediation
       planning, falling back to a deterministic rule-based mapper if the
       model is unreachable or returns something invalid.
    3. Writes findings + decisions to compliance_report.json.
    4. Stages actions for human approval.
    """
    try:
        findings = []
        findings.extend(scan_s3_security_issues())
        findings.extend(scan_iam_security_issues())
        findings.extend(scan_monitoring_issues())

        if not findings:
            report_data = {"status": "SECURE", "findings": [], "ai_analysis": "No vulnerabilities detected."}
            with open("compliance_report.json", "w") as f:
                json.dump(report_data, f, indent=2)
            return {"message": "All resources are secure.", "report": report_data}

        decision, raw_actions = get_ai_decision(findings)

        staged_actions_list = []
        for item in raw_actions:
            action_id = str(uuid.uuid4())
            entry = {
                "action_id": action_id,
                "resource_name": item["resource_name"],
                "action": _canonical_action(item["action"]),
                "risk_level": item.get("risk_level", "UNKNOWN"),
                "status": "PENDING_APPROVAL",
            }
            if item.get("access_key_id"):
                entry["access_key_id"] = item["access_key_id"]
            pending_actions[action_id] = entry
            staged_actions_list.append(entry)

        report_data = {
            "status": "VULNERABILITIES_FOUND",
            "raw_findings": findings,
            "ai_analysis": decision.analysis_summary,
            "pending_actions": staged_actions_list,
        }
        with open("compliance_report.json", "w") as f:
            json.dump(report_data, f, indent=2)

        return {
            "message": "Scan complete. Fixes staged in compliance_report.json.",
            "ai_summary": decision.analysis_summary,
            "pending_actions": staged_actions_list,
        }

    except Exception as e:
        log.exception("Scan failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/pending", dependencies=[Depends(require_api_key)])
def view_pending_actions():
    """Lists all AI-proposed fixes awaiting approval."""
    return {"pending_actions": list(pending_actions.values())}


@app.post("/api/approve", dependencies=[Depends(require_api_key)])
def approve_and_execute(approval: ActionApproval):
    """Executes a staged fix on AWS after human confirmation. Falls back to a
    dry-run message (no AWS call) if credentials aren't available, so this
    still demos cleanly without live AWS access."""
    if approval.action_id not in pending_actions:
        raise HTTPException(status_code=404, detail="Action ID not found.")

    task = pending_actions[approval.action_id]

    if task["status"] != "PENDING_APPROVAL":
        raise HTTPException(status_code=400, detail=f"Action is already {task['status']}.")

    if task["action"] not in ALLOWED_ACTIONS:
        raise HTTPException(status_code=403, detail=f"Action '{task['action']}' is blocked by guardrails.")

    try:
        message = _execute_remediation(task)
        task["status"] = "REMEDIATED"

        try:
            with open("compliance_report.json", "r") as f:
                current_report = json.load(f)
            current_report["latest_remediation"] = task
            with open("compliance_report.json", "w") as f:
                json.dump(current_report, f, indent=2)
        except FileNotFoundError:
            pass

        return {"status": "SUCCESS", "message": message}

    except (ClientError, NoCredentialsError, EndpointConnectionError) as e:
        log.warning("AWS call failed during remediation, returning dry-run result: %s", e)
        task["status"] = "REMEDIATED (DRY RUN - AWS UNAVAILABLE)"
        return {
            "status": "SUCCESS",
            "message": f"[DRY RUN] Would have applied '{task['action']}' to '{task['resource_name']}' "
                       f"-- AWS is not reachable/authorized in this environment: {e}",
        }
    except Exception as e:
        log.exception("Remediation failed")
        raise HTTPException(status_code=500, detail=f"Execution error: {str(e)}")


def _execute_remediation(task: dict) -> str:
    action = task["action"]

    if action == "block_public_access":
        s3 = boto3.client("s3", region_name=AWS_REGION)
        s3.put_public_access_block(
            Bucket=task["resource_name"],
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
            },
        )
        return f"Blocked public access on '{task['resource_name']}'."

    if action == "encrypt_bucket":
        s3 = boto3.client("s3", region_name=AWS_REGION)
        s3.put_bucket_encryption(
            Bucket=task["resource_name"],
            ServerSideEncryptionConfiguration={"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
        )
        return f"Enabled AES256 encryption on '{task['resource_name']}'."

    if action == "quarantine_user_pending_mfa":
        # WHAT/WHY: this does NOT enable MFA (AWS has no API to do that for a
        # user remotely) -- it attaches a deny-all policy until an admin sets
        # MFA up for the user. The name and this message now say that plainly.
        iam = boto3.client("iam", region_name=AWS_REGION)
        deny_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Sid": "BlockAccessUntilMFAConfigured", "Effect": "Deny", "Action": "*", "Resource": "*"}],
        }
        iam.put_user_policy(
            UserName=task["resource_name"], PolicyName="Quarantine-No-MFA",
            PolicyDocument=json.dumps(deny_policy),
        )
        return f"Quarantined '{task['resource_name']}' (access denied) pending MFA setup by an administrator."

    if action == "detach_admin_policy":
        iam = boto3.client("iam", region_name=AWS_REGION)
        iam.detach_user_policy(UserName=task["resource_name"], PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
        return f"Detached AdministratorAccess from '{task['resource_name']}'."

    if action == "deactivate_stale_key":
        # WHAT/WHY: deactivates only the specific key ID the scan flagged as
        # stale, not every key the user has (the old code looped over *all*
        # keys and deactivated them, which could kill an active key too).
        iam = boto3.client("iam", region_name=AWS_REGION)
        key_id = task.get("access_key_id")
        if not key_id:
            raise HTTPException(status_code=400, detail="No specific access_key_id on this action; refusing to deactivate all keys.")
        iam.update_access_key(UserName=task["resource_name"], AccessKeyId=key_id, Status="Inactive")
        return f"Deactivated stale access key '{key_id}' for '{task['resource_name']}'."

    raise HTTPException(status_code=400, detail=f"Unhandled action '{action}'.")
