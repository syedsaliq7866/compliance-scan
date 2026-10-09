"""
Remediation guardrails and execution -- moved out of main.py unchanged, so
both the FastAPI app and the LangGraph agent's "remediate" node can share
the same whitelist and execution logic.
"""
import json
import os

import boto3
from fastapi import HTTPException

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

# Guardrail: Whitelist of allowed automated actions. Nothing outside this
# list can ever be executed, no matter what the agent proposes.
ALLOWED_ACTIONS = [
    "block_public_access",
    "encrypt_bucket",
    "quarantine_user_pending_mfa",
    "deactivate_stale_key",
    "detach_admin_policy",
]
_ACTION_ALIASES = {"enable_mfa": "quarantine_user_pending_mfa", "deactivate_key": "deactivate_stale_key"}


def canonical_action(name: str) -> str:
    return _ACTION_ALIASES.get(name, name)


def execute_remediation(task: dict) -> str:
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
        iam = boto3.client("iam", region_name=AWS_REGION)
        key_id = task.get("access_key_id")
        if not key_id:
            raise HTTPException(status_code=400, detail="No specific access_key_id on this action; refusing to deactivate all keys.")
        iam.update_access_key(UserName=task["resource_name"], AccessKeyId=key_id, Status="Inactive")
        return f"Deactivated stale access key '{key_id}' for '{task['resource_name']}'."

    raise HTTPException(status_code=400, detail=f"Unhandled action '{action}'.")
