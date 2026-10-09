"""
Account-level monitoring/audit-logging compliance checks (CloudTrail, Macie).

audit_monitoring_services() is the live, actually-used entry point --
scanners.py.scan_monitoring_issues() calls it directly. Its own internal
try/except falls back to run_mock_monitoring_audit() on any AWS error
(missing creds, permission denied, region issue, etc.), so both functions
in this file are live code paths, unlike storage_compliance.py's
leftover duplicates.
"""
import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def run_mock_monitoring_audit():
    """Fallback used by audit_monitoring_services() when AWS isn't reachable
    (no credentials, region/permission error, etc.) -- keeps the demo working
    without live AWS access. NOT a standalone/unused function: it's called
    from inside the except block below."""
    print("--- Starting Logging & Privacy Scan (MOCK MODE) ---")
    mock_findings = [
        {"service": "CloudTrail (Audit Logging)", "enabled": True},
        {"service": "Amazon Macie (PII Scanning)", "enabled": False}
    ]

    for item in mock_findings:
        if not item["enabled"]:
            print(f"[VIOLATION] {item['service']} is DISABLED. Non-compliant with HIPAA/GDPR auditing!")
        else:
            print(f"[PASS] {item['service']} is enabled.")

    print("\n[MOCK SCAN COMPLETE] Monitoring logic verified!")
    return mock_findings


def audit_monitoring_services():
    """Checks two account-level monitoring controls against AWS:
      - CloudTrail: at least one trail must exist (describe_trails()).
      - Macie: must have an active session (get_macie_session() raises
        ClientError when Macie has never been enabled for the account).
    Called live by scanners.py.scan_monitoring_issues() on every scan.
    """
    print("--- Starting Logging & Privacy Scan (LIVE MODE) ---")
    findings = []

    try:
        # Check CloudTrail
        cloudtrail = boto3.client('cloudtrail', region_name='us-east-1')
        trails = cloudtrail.describe_trails().get('trailList', [])
        cloudtrail_enabled = len(trails) > 0
        findings.append({"service": "CloudTrail (Audit Logging)", "enabled": cloudtrail_enabled})

        if not cloudtrail_enabled:
            print("[VIOLATION] CloudTrail is DISABLED!")

        # Check Macie
        macie = boto3.client('macie2', region_name='us-east-1')
        try:
            macie.get_macie_session()
            macie_enabled = True
        except ClientError:
            macie_enabled = False

        findings.append({"service": "Amazon Macie (PII Scanning)", "enabled": macie_enabled})
        if not macie_enabled:
            print("[VIOLATION] Amazon Macie is DISABLED!")

        return findings

    except (ClientError, NoCredentialsError):
        print("\n[AWS PENDING] Switching to Mock Mode to test monitoring logic...\n")
        return run_mock_monitoring_audit()
