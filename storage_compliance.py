"""
S3 storage compliance checks.

Two public helpers are the live, actually-used part of this file --
scanners.py imports both and calls them per-bucket from
scan_s3_security_issues():
  - check_s3_bucket_encryption()
  - check_s3_bucket_versioning()

The rest of this file (run_mock_audit, audit_storage_and_iam) predates the
FastAPI/agentic refactor and is NOT called from anywhere in the running
app -- scanners.py.scan_s3_security_issues() re-implements an equivalent
live-scan-with-mock-fallback directly instead of calling audit_storage_and_iam()
here. Left in place as reference/legacy rather than deleted; safe to remove
once you've confirmed nothing external still imports it.
"""
import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def check_s3_bucket_encryption(s3_client, bucket_name):
    """Returns True if the bucket has server-side encryption configured at all
    (any rule), False otherwise. Used live by scanners.py."""
    try:
        response = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = response['ServerSideEncryptionConfiguration']['Rules']
        return True
    except ClientError:
        return False


def check_s3_bucket_versioning(s3_client, bucket_name):
    """Returns True only if versioning is explicitly 'Enabled' (not merely
    present/suspended). Used live by scanners.py."""
    try:
        response = s3_client.get_bucket_versioning(Bucket=bucket_name)
        return response.get('Status') == 'Enabled'
    except ClientError:
        return False


# --- Everything below this line is unused by the running app -----------
# Kept as the original, pre-refactor standalone scan logic. scanners.py's
# scan_s3_security_issues() does the equivalent live-scan + mock-fallback
# itself and never calls audit_storage_and_iam() or run_mock_audit().

def run_mock_audit():
    """UNUSED -- no longer called by the running app. Kept as reference."""
    print("--- Starting Storage Compliance Scan (MOCK MODE) ---")
    mock_buckets = [
        {"Name": "company-public-logs", "encrypted": False, "versioning": False},
        {"Name": "secure-financial-records", "encrypted": True, "versioning": True},
        {"Name": "user-backups-2026", "encrypted": False, "versioning": True}
    ]

    findings = []
    for bucket in mock_buckets:
        name = bucket["Name"]
        enc_status = bucket["encrypted"]
        ver_status = bucket["versioning"]

        if not enc_status:
            print(f"[VIOLATION] S3 Bucket '{name}' is NOT encrypted!")
        if not ver_status:
            print(f"[VIOLATION] S3 Bucket '{name}' does NOT have versioning enabled (No Backups)!")

        findings.append({
            "bucket": name,
            "encrypted": enc_status,
            "versioning": ver_status
        })

    print("\n[MOCK SCAN COMPLETE] Storage logic verified!")
    return findings


def audit_storage_and_iam():
    """UNUSED -- no longer called by the running app. Kept as reference;
    scan_s3_security_issues() in scanners.py is the live equivalent."""
    print("--- Starting Storage Compliance Scan (LIVE MODE) ---")
    try:
        s3 = boto3.client('s3', region_name='us-east-1')
        buckets = s3.list_buckets().get('Buckets', [])

        findings = []
        for bucket in buckets:
            name = bucket['Name']
            is_encrypted = check_s3_bucket_encryption(s3, name)
            is_versioned = check_s3_bucket_versioning(s3, name)

            if not is_encrypted:
                print(f"[VIOLATION] S3 Bucket '{name}' is NOT encrypted!")
            if not is_versioned:
                print(f"[VIOLATION] S3 Bucket '{name}' does NOT have versioning enabled!")

            findings.append({
                "bucket": name,
                "encrypted": is_encrypted,
                "versioning": is_versioned
            })

        return findings

    except (ClientError, NoCredentialsError):
        print("\n[AWS PENDING] Switching to Mock Mode to test script logic...\n")
        return run_mock_audit()
