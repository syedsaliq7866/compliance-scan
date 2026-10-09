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
# list can ever be executed, no matter what the agent proposes -- enforced
# twice: once by agent_graph.py at staging time (a proposal for anything
# not in this list is rejected before a human even sees it), and again
# here at execution time via execute_remediation()'s final `raise` below.
ALLOWED_ACTIONS = [
    "block_public_access",
    "encrypt_bucket",
    "quarantine_user_pending_mfa",
    "deactivate_stale_key",
    "detach_admin_policy",
]

# Older/friendlier names the agent or an earlier API version might still
# send in -- mapped to the current canonical action name so both resolve
# to the same ALLOWED_ACTIONS entry and the same execute_remediation() branch.
_ACTION_ALIASES = {"enable_mfa": "quarantine_user_pending_mfa", "deactivate_key": "deactivate_stale_key"}


def canonical_action(name: str) -> str:
    """Resolves an alias (see _ACTION_ALIASES) to its canonical action name;
    returns the name unchanged if it isn't an alias."""
    return _ACTION_ALIASES.get(name, name)


def execute_remediation(task: dict) -> str:
    """Applies one approved fix to live AWS via boto3. `task` is a staged
    pending_actions entry (action_id, resource_name, action, ...) -- only
    reached after a human has already approved it via POST /api/approve.
    Returns a human-readable confirmation string; raises HTTPException for
    a guardrail failure (unknown action, missing required field)."""
    action = task["action"]

    if action == "block_public_access":
        # S3 finding: "Public Access Not Fully Blocked" / "No Public Access
        # Block Configured" -- locks the bucket down on all four public-access
        # dimensions at once (ACLs, bucket policy, both at the account level too).
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
        # S3 finding: "Bucket is not encrypted" -- turns on default AES256
        # server-side encryption so new objects are encrypted at rest even
        # if the uploader doesn't explicitly request it.
        s3 = boto3.client("s3", region_name=AWS_REGION)
        s3.put_bucket_encryption(
            Bucket=task["resource_name"],
            ServerSideEncryptionConfiguration={"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
        )
        return f"Enabled AES256 encryption on '{task['resource_name']}'."

    if action == "quarantine_user_pending_mfa":
        # IAM finding: "MFA is not enabled for this user" -- this is
        # containment, not a real fix: it attaches an explicit Deny-all
        # inline policy so the account can't be used until an administrator
        # manually sets up MFA and removes this policy. It deliberately does
        # NOT enable MFA on the user's behalf (an automated agent shouldn't
        # be able to do that), so a post-fix verify scan will keep reporting
        # "MFA is not enabled" as true -- that's expected, not a failure.
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
        # IAM finding: "User has dangerous direct AdministratorAccess attached"
        # -- removes the AWS-managed AdministratorAccess policy directly from
        # the user. Does not touch admin access granted via a group or role.
        iam = boto3.client("iam", region_name=AWS_REGION)
        iam.detach_user_policy(UserName=task["resource_name"], PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
        return f"Detached AdministratorAccess from '{task['resource_name']}'."

    if action == "deactivate_stale_key":
        # IAM finding: "Access key is severely stale (>90 days old)" --
        # deactivates (not deletes) the one specific key the finding flagged,
        # identified by access_key_id. Refuses to run if that field is
        # missing, rather than guessing and deactivating every key the user
        # has (which could lock out a key that's actually fine).
        iam = boto3.client("iam", region_name=AWS_REGION)
        key_id = task.get("access_key_id")
        if not key_id:
            raise HTTPException(status_code=400, detail="No specific access_key_id on this action; refusing to deactivate all keys.")
        iam.update_access_key(UserName=task["resource_name"], AccessKeyId=key_id, Status="Inactive")
        return f"Deactivated stale access key '{key_id}' for '{task['resource_name']}'."

    # Reached only if `action` somehow isn't one of the five branches above --
    # should be unreachable in practice since agent_graph.py already rejects
    # anything outside ALLOWED_ACTIONS at staging time, but kept as a final
    # guardrail in case this function is ever called from a new code path
    # that skips that check.
    raise HTTPException(status_code=400, detail=f"Unhandled action '{action}'.")
