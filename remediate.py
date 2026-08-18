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
        s3 = boto3.client('s3', region_name='us-east-1')
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
        print("[ERROR] compliance_report.json not found. Run main.py first.")
        return

    storage_findings = report.get("storage_findings", [])
    iam_findings = report.get("iam_findings", [])
    
    # 2. Check if we are running in Mock Mode
    try:
        sts = boto3.client('sts')
        sts.get_caller_identity()
        is_mock = False
    except (ClientError, NoCredentialsError):
        is_mock = True
        print("[AWS PENDING] Running remediation in MOCK MODE.\n")

    # 3. Remediate Storage Violations
    print("[1] FIXING STORAGE VIOLATIONS:")
    for item in storage_findings:
        if not item.get("encrypted", True):
            remediate_s3_encryption(item["bucket"], is_mock)

    # 4. Address IAM Violations
    print("\n[2] ADDRESSING IAM VIOLATIONS:")
    for item in iam_findings:
        if item.get("issue") == "MFA Missing":
            remediate_iam_mfa(item["user"])
        elif item.get("issue") == "Old Access Keys":
            print(f"  -> [WARNING] IAM User '{item['user']}' needs keys rotated. Auto-deactivation disabled for safety.")

    print("\n==============================================")
    print("         AUTO-REMEDIATION COMPLETE            ")
    print("==============================================")

if __name__ == "__main__":
    run_remediation()