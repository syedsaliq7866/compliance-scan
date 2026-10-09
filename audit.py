"""
*** LEGACY / UNUSED -- not imported anywhere in the running app. ***

Earliest version of the S3 audit, from before scanners.py/remediation.py/
agent_graph.py existed. Writes its own compliance_report.json directly
(a different, incompatible shape from the one main.py writes now) and is
only ever run standalone (`python audit.py`), never imported.

Safe to delete once confirmed nothing outside this file references it; kept
for now rather than removed outright.
"""

import boto3
import json

def scan_s3_buckets():
    s3_client = boto3.client('s3')
    response = s3_client.list_buckets()
    
    findings = []
    
    for bucket in response.get('Buckets', []):
        bucket_name = bucket['Name']
        print(f"Scanning bucket: {bucket_name}...")

        # Check Public Access Block setting
        public_access_status = "Secure (Blocked)"
        try:
            pub_config = s3_client.get_public_access_block(Bucket=bucket_name)
            pab = pub_config['PublicAccessBlockConfiguration']
            if not pab.get('BlockAllPublicAccess', False) and not pab.get('BlockPublicAcls', False):
                public_access_status = "Public Access Open (Violation)"
        except Exception:
            # If no public access block exists at all, it's open/unprotected
            public_access_status = "No Public Access Block Configured (Violation)"

        findings.append({
            "resource": bucket_name,
            "service": "S3",
            "compliance_issue": "Public Access Exposure",
            "status": public_access_status
        })

    report = {"violations": findings}
    
    with open("compliance_report.json", "w") as f:
        json.dump(report, f, indent=2)
        
    print("\nAudit complete! Check 'compliance_report.json' to see your findings.")

if __name__ == "__main__":
    scan_s3_buckets()