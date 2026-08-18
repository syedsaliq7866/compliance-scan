import json
from storage_compliance import audit_storage_and_iam
from iam_compliance import audit_iam_security
from monitoring_compliance import audit_monitoring_services

def generate_report(storage, iam, monitoring):
    print("\n==============================================")
    print("   FULL HIPAA & GDPR COMPLIANCE FINAL REPORT  ")
    print("==============================================")
    
    total_violations = 0

    print("\n[1] STORAGE COMPLIANCE (Data at Rest & Recovery):")
    for item in storage:
        if not item.get('encrypted'):
            total_violations += 1
            print(f"  - [HIGH] S3 Bucket '{item['bucket']}' lacks encryption (HIPAA/GDPR Violation).")
        if not item.get('versioning'):
            total_violations += 1
            print(f"  - [MEDIUM] S3 Bucket '{item['bucket']}' lacks versioning (Disaster Recovery Risk).")

    print("\n[2] IAM SECURITY (Access & Authentication):")
    for item in iam:
        total_violations += 1
        print(f"  - [HIGH] User '{item['user']}': {item['issue']}")

    print("\n[3] LOGGING & PRIVACY (Auditing & PII):")
    for item in monitoring:
        if not item['enabled']:
            total_violations += 1
            print(f"  - [CRITICAL] {item['service']} is missing. Fails regulatory audit standards!")

    print("\n----------------------------------------------")
    print(f" TOTAL REGULATORY VIOLATIONS DETECTED: {total_violations}")
    print("----------------------------------------------")

    report_data = {
        "storage_findings": storage,
        "iam_findings": iam,
        "monitoring_findings": monitoring,
        "total_violations": total_violations
    }
    
    with open("compliance_report.json", "w") as f:
        json.dump(report_data, f, indent=4)
        
    print("\n[SUCCESS] Full regulatory report saved to 'compliance_report.json'!\n")

def main():
    print("Initializing Automated HIPAA/GDPR Cloud Scanner...\n")
    storage_results = audit_storage_and_iam()
    iam_results = audit_iam_security()
    monitoring_results = audit_monitoring_services()
    
    generate_report(storage_results, iam_results, monitoring_results)

if __name__ == "__main__":
    main()