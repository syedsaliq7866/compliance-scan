import json
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

def remediate_s3_encryption(bucket_name, is_mock=False):
    """Enables AES256 default encryption on an S3 bucket."""
    print(f"  -> Attempting to encrypt S3 bucket: '{bucket_name}'...")
    if is_mock:
        print(f"     [MOCK REMEDIATED] Successfully enabled AES256 encryption on '{bucket_name}'.")
        return True
        
    try:
        s3 = boto3.client('s3')
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]
            }
        )
        print(f"     [REMEDIATED] Successfully enabled AES256 encryption on '{bucket_name}'.")
        return True
    except Exception as e:
        print(f"     [FAILED] Could not encrypt '{bucket_name}': {e}")
        return False

def remediate_s3_public_access(bucket_name, is_mock=False):
    """Enables Block Public Access on an S3 bucket."""
    print(f"  -> Attempting to block public access on S3 bucket: '{bucket_name}'...")
    if is_mock:
        print(f"     [MOCK REMEDIATED] Successfully blocked public access on '{bucket_name}'.")
        return True
        
    try:
        s3 = boto3.client('s3')
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        print(f"     [REMEDIATED] Successfully locked down public access on '{bucket_name}'.")
        return True
    except Exception as e:
        print(f"     [FAILED] Could not block public access for '{bucket_name}': {e}")
        return False

def remediate_iam_mfa(username):
    """Notifies that MFA requires manual administrative action."""
    print(f"  -> [ACTION REQUIRED] Cannot auto-enable MFA for '{username}'. An administrator must enforce this policy.")

def run_remediation():
    print("\n==============================================")
    print("      STARTING AUTO-REMEDIATION PROCESS       ")
    print("==============================================\n")
    
    # 1. Read the report
    try:
        with open("compliance_report.json", "r") as f:
            report = json.load(f)
    except FileNotFoundError:
        print("[ERROR] compliance_report.json not found. Run your scan first.")
        return

    # Support both custom structure and standard violation list
    storage_findings = report.get("storage_findings", [])
    iam_findings = report.get("iam_findings", [])
    general_violations = report.get("violations", [])
    
    # 2. Check if running in Live AWS or Mock Mode
    try:
        sts = boto3.client('sts')
        sts.get_caller_identity()
        is_mock = False
        print("[AWS LIVE] Connected to AWS. Applying real fixes...\n")
    except (ClientError, NoCredentialsError):
        is_mock = True
        print("[AWS PENDING] Running remediation in MOCK MODE.\n")

    # 3. Remediate Storage Violations (Encryption & Public Access)
    print("[1] FIXING STORAGE VIOLATIONS:")
    
    # From structured storage_findings
    for item in storage_findings:
        bucket = item.get("bucket")
        if not item.get("encrypted", True):
            remediate_s3_encryption(bucket, is_mock)
        if item.get("public_access_open", False) or not item.get("public_blocked", True):
            remediate_s3_public_access(bucket, is_mock)

    # From audit.py general violations list
    for item in general_violations:
        if item.get("service") == "S3":
            bucket = item.get("resource")
            if "Public Access Open" in item.get("status", "") or "No Public Access" in item.get("status", ""):
                remediate_s3_public_access(bucket, is_mock)

    # 4. Address IAM Violations
    print("\n[2] ADDRESSING IAM VIOLATIONS:")
    for item in iam_findings:
        if item.get("issue") == "MFA Missing":
            remediate_iam_mfa(item["user"])
        elif item.get("issue") == "Old Access Keys":
            print(f"  -> [WARNING] IAM User '{item['user']}' needs keys rotated. Auto-deactivation disabled for safety.")

    print("\n==============================================")
    print("         AUTO-REMEDIATION COMPLETE            ")
    print("==============================================\n")

if __name__ == "__main__":
    run_remediation()