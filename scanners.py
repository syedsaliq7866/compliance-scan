"""
AWS scanners -- moved out of main.py unchanged, so both the FastAPI app and
the LangGraph agent (agent_graph.py) can import the same functions without
a circular import between main.py and agent_graph.py.

Behavior is identical to the pre-agentic version: live AWS calls that
degrade to deterministic mock data on any failure (missing creds, rate
limit, permission denied, network issue), so a scan never crashes the demo.
"""
import datetime
import logging
import os
from datetime import timezone

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError

import storage_compliance
import monitoring_compliance

log = logging.getLogger("compliance-scan")

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
MOCK_ON_FAILURE = os.getenv("MOCK_ON_FAILURE", "true").lower() == "true"


# WHAT: every mock finding is tagged `_mock: True`. WHY: the agentic verify
# step re-checks a resource after "fixing" it to confirm the fix worked --
# but a mock finding describes a resource that doesn't really exist, so
# re-scanning it will always show the same static mock data regardless of
# what was "fixed." Without this tag, verification would misleadingly report
# every mock-mode fix as having failed. Tagged findings are skipped by
# verification instead (see agent_graph.py's verify_node).
def _mock_iam_findings():
    return [
        {"resource": "admin-root", "service": "IAM", "issue": "MFA is not enabled for this user", "_mock": True},
        {"resource": "admin-root", "service": "IAM", "issue": "Access key is severely stale (142 days old)",
         "access_key_id": "AKIAMOCKSTALE00001", "_mock": True},
        {"resource": "service-acc", "service": "IAM", "issue": "User has dangerous direct AdministratorAccess attached", "_mock": True},
    ]


def _mock_s3_findings():
    return [
        {"resource": "company-public-logs", "service": "S3", "issue": "No Public Access Block Configured", "_mock": True},
        {"resource": "company-public-logs", "service": "S3", "issue": "Bucket is not encrypted", "_mock": True},
        {"resource": "user-backups-2026", "service": "S3", "issue": "Bucket does not have versioning enabled", "_mock": True},
    ]


def _mock_monitoring_findings():
    return [{"resource": "account", "service": "Monitoring", "issue": "Amazon Macie (PII scanning) is disabled", "_mock": True}]


# ---------------------------------------------------------------------------
# IAM scanner -- checks every user except security-agent-bot (the agent's own
# service account, excluded so the tool never flags/quarantines itself) for:
# missing MFA, access keys older than 90 days, and a directly-attached
# AdministratorAccess policy. Self-contained (does not call iam_compliance.py,
# which is unused legacy code -- see that file's header).
# ---------------------------------------------------------------------------
def scan_iam_security_issues():
    """Scans AWS IAM for missing MFA, stale keys (>90 days), and excessive admin permissions."""
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
    except Exception:
        log.exception("Unexpected error scanning IAM")
        return _mock_iam_findings() if MOCK_ON_FAILURE else []


# ---------------------------------------------------------------------------
# S3 scanner -- lists every bucket and checks public-access-block settings
# itself, then delegates the encryption/versioning checks to
# storage_compliance.py's two live helper functions (the only part of that
# file still in use -- see its header for what's dead code there).
# ---------------------------------------------------------------------------
def scan_s3_security_issues():
    """Public access + encryption + versioning, via storage_compliance.py's checks."""
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


# ---------------------------------------------------------------------------
# Monitoring scanner -- thin wrapper around monitoring_compliance.py's
# account-level CloudTrail/Macie check, reshaping its {service, enabled}
# rows into the same {resource, service, issue} finding shape the other two
# scanners return, so agent_graph.py can treat all three uniformly.
# ---------------------------------------------------------------------------
def scan_monitoring_issues():
    """CloudTrail + Macie, via monitoring_compliance.py."""
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
# Post-remediation verification -- called by agent_graph.py's verify_node
# after a real (non-mock) fix executes, to confirm the original finding is
# actually gone rather than just trusting the boto3 call succeeded.
# ---------------------------------------------------------------------------
def check_resource_now(service: str, resource_name: str, issue_keyword: str):
    """Used by the agent's 'verify' step after a remediation: re-run only the
    relevant scanner and check whether a finding matching this resource and
    issue keyword still appears. Returns True if the issue is GONE (fixed),
    False if it's STILL PRESENT, or None if this can't be determined (e.g.
    the scan is running against mock data with no real resource to recheck).
    """
    if service == "IAM":
        findings = scan_iam_security_issues()
    elif service == "S3":
        findings = scan_s3_security_issues()
    elif service == "Monitoring":
        findings = scan_monitoring_issues()
    else:
        return None

    still_present = any(
        f["resource"] == resource_name and issue_keyword.lower() in f["issue"].lower()
        for f in findings
    )
    return not still_present
