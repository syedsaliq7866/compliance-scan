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