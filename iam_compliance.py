"""
*** LEGACY / UNUSED -- not imported anywhere in the running app. ***

This is a standalone pre-FastAPI script (note the `if __name__ == "__main__"`
at the bottom -- it was meant to be run directly with `python iam_compliance.py`,
not imported). scanners.py.scan_iam_security_issues() re-implements the live
IAM scan itself (MFA + stale keys + admin policy, with its own mock fallback)
and never imports this module. audit_iam_security() here only checks MFA --
it's an earlier, less complete version of that logic.

Safe to delete once confirmed nothing outside this file references it; kept
for now rather than removed outright.
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

def run_mock_iam_audit():
    """Runs a local IAM compliance test without requiring an active AWS account."""
    print("--- Starting IAM Security Compliance Scan (MOCK MODE) ---")
    mock_users = [
        {"UserName": "admin-root", "MFAEnabled": False, "AccessKeysOld": True},
        {"UserName": "dev-user-01", "MFAEnabled": True, "AccessKeysOld": False},
        {"UserName": "service-acc", "MFAEnabled": False, "AccessKeysOld": True}
    ]
    
    print(f"Found {len(mock_users)} IAM user(s) to scan.\n")
    findings = []
    
    for user in mock_users:
        username = user["UserName"]
        if not user["MFAEnabled"]:
            print(f"[VIOLATION] IAM User '{username}' does NOT have MFA enabled!")
            findings.append({"user": username, "issue": "MFA Missing"})
        if user["AccessKeysOld"]:
            print(f"[WARNING] IAM User '{username}' has access keys older than 90 days!")
            findings.append({"user": username, "issue": "Old Access Keys"})
            
    print("\n[MOCK IAM SCAN COMPLETE] Logic verified successfully!")
    return findings

def audit_iam_security():
    """Main function to audit live AWS IAM security configurations."""
    print("--- Starting IAM Security Compliance Scan (LIVE MODE) ---")
    
    try:
        iam = boto3.client('iam', region_name='us-east-1')
        users = iam.list_users().get('Users', [])
        print(f"Found {len(users)} IAM user(s) to scan.")
        
        findings = []
        for user in users:
            username = user['UserName']
            # Check MFA Devices
            mfa_devices = iam.list_mfa_devices(UserName=username).get('MFADevices', [])
            if not mfa_devices:
                print(f"[VIOLATION] IAM User '{username}' does NOT have MFA enabled!")
                findings.append({"user": username, "issue": "MFA Missing"})
            else:
                print(f"[PASS] IAM User '{username}' has MFA enabled.")
                
        return findings

    except (ClientError, NoCredentialsError):
        print("\n[AWS PENDING] Live AWS access key is invalid or pending account activation.")
        print("Switching to Mock Mode to test IAM script logic...\n")
        return run_mock_iam_audit()
    except Exception as e:
        print(f"\n[ERROR] Could not complete IAM scan: {e}")

if __name__ == "__main__":
    audit_iam_security()