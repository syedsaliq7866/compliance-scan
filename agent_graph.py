"""
Agentic compliance engine, built on LangGraph.

WHAT changed from the old get_ai_decision()/single JSON-mode prompt:
  The old version made exactly one call to Ollama per scan: "here are the
  findings, return a JSON decision." It never decided anything -- it
  classified. This version gives the model actual tools (the scanners
  themselves) and lets it decide which to call, in what order, and when
  it's done investigating, then separately lets it re-check a resource
  after a fix is applied to confirm the fix actually worked. That
  investigate -> propose -> (human approves) -> remediate -> verify loop is
  what makes this an agent rather than a classifier.

WHY two separate graphs instead of one graph paused mid-run:
  /api/scan can produce several pending actions in one pass, and a human
  may approve them individually, at different times, over Swagger or n8n.
  Keeping a single LangGraph run checkpointed and "interrupted" across
  however many separate HTTP requests that takes is fragile to get right
  under demo conditions. Instead: one small graph (investigate -> stage)
  runs synchronously inside /api/scan and ends; a second small graph
  (remediate -> verify) runs synchronously inside /api/approve, once per
  approved action. The human-approval pause is just "the gap between two
  separate API calls" -- simpler, and exactly as safe, since nothing in the
  remediate/verify graph exists until a human has already hit /api/approve.

WHY it still falls back to fixed-order scanning + rule-based decisions:
  Local 8B models are flaky at tool-calling compared to hosted frontier
  models. If the investigate loop fails for any reason (Ollama down,
  timeout, malformed tool call, model refuses to call any tool), the node
  falls back to calling all three scanners directly and using the same
  deterministic rule map the pre-agentic version used -- so a flaky local
  model degrades the demo from "agentic" to "still correct," never to
  "broken."
"""
import json
import logging
import os
import uuid

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import tool
from langchain_ollama import ChatOllama
from langgraph.graph import StateGraph, END
from typing import Any, Dict, List, Optional, TypedDict

import scanners
import remediation

log = logging.getLogger("compliance-scan")

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
OLLAMA_TIMEOUT_SECONDS = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "8"))
MAX_AGENT_STEPS = int(os.getenv("AGENT_MAX_STEPS", "6"))

# Maps each guardrail action to the (service, issue-keyword) it should
# verify against after remediation, and what it fixes in rule-based mode.
_RULE_MAP = {
    "MFA is not enabled": ("quarantine_user_pending_mfa", "HIGH", "IAM"),
    "AdministratorAccess": ("detach_admin_policy", "CRITICAL", "IAM"),
    "severely stale": ("deactivate_stale_key", "MEDIUM", "IAM"),
    "Public Access": ("block_public_access", "HIGH", "S3"),
    "not encrypted": ("encrypt_bucket", "MEDIUM", "S3"),
}
_ACTION_VERIFY_KEYWORD = {
    "quarantine_user_pending_mfa": ("IAM", "MFA is not enabled"),
    "detach_admin_policy": ("IAM", "AdministratorAccess"),
    "deactivate_stale_key": ("IAM", "severely stale"),
    "block_public_access": ("S3", "Public Access"),
    "encrypt_bucket": ("S3", "not encrypted"),
}


# ---------------------------------------------------------------------------
# Tools the agent can call during investigation. Each wraps an existing,
# already-reliable scanner -- the agent decides WHEN to call them, the
# scanner itself is untouched.
# ---------------------------------------------------------------------------
@tool
def get_iam_findings() -> str:
    """Scan AWS IAM for missing MFA, stale access keys, and over-broad admin policies. Returns a JSON list of findings."""
    return json.dumps(scanners.scan_iam_security_issues())


@tool
def get_s3_findings() -> str:
    """Scan S3 buckets for public access, missing encryption, and missing versioning. Returns a JSON list of findings."""
    return json.dumps(scanners.scan_s3_security_issues())


@tool
def get_monitoring_findings() -> str:
    """Check whether CloudTrail and Macie are enabled for the account. Returns a JSON list of findings."""
    return json.dumps(scanners.scan_monitoring_issues())


@tool
def stage_remediation(resource_name: str, service: str, action: str, risk_level: str, reasoning: str, access_key_id: str = "") -> str:
    """Propose a remediation for one finding. `action` MUST be one of: block_public_access,
    encrypt_bucket, quarantine_user_pending_mfa, deactivate_stale_key, detach_admin_policy.
    `service` must be one of: IAM, S3, Monitoring. `risk_level` must be one of: LOW, MEDIUM, HIGH, CRITICAL.
    `reasoning` is a short, specific explanation of why this finding is risky and why this action fixes it.
    Call this once per finding that needs a fix. Nothing is executed yet -- it only stages the proposal
    for a human to review."""
    return f"Staged proposal: {action} on {resource_name} (risk: {risk_level})."


@tool
def finish_investigation() -> str:
    """Call this once you have checked IAM, S3, and monitoring, and have staged a remediation for every
    finding that needs one. Signals that your investigation is complete."""
    return "Investigation marked complete."


_TOOLS = [get_iam_findings, get_s3_findings, get_monitoring_findings, stage_remediation, finish_investigation]
_TOOLS_BY_NAME = {t.name: t for t in _TOOLS}

_SYSTEM_PROMPT = f"""You are an autonomous cloud compliance agent for HIPAA/GDPR-style AWS audits.

Investigate the account by calling get_iam_findings, get_s3_findings, and get_monitoring_findings
(in any order -- call each at least once). For every finding that represents a real risk, call
stage_remediation with a specific, concrete reasoning string explaining the risk and the fix.
Only use these exact action values: {json.dumps(remediation.ALLOWED_ACTIONS)}.
Monitoring findings (CloudTrail, Macie) have NO allowed action at all right now -- if
get_monitoring_findings returns an issue, note it mentally and move on, but do NOT call
stage_remediation for it. Spend your effort on IAM and S3 findings instead, since those are the
only ones you can actually propose a fix for.
When you've checked all three areas and staged a remediation for every IAM/S3 finding that needs
one, call finish_investigation. Do not call finish_investigation before you have checked all
three areas. Do not invent resources -- only act on what the scan tools actually return.
"""


class ScanState(TypedDict, total=False):
    findings: List[Dict[str, Any]]
    proposed_actions: List[Dict[str, Any]]
    tool_calls_log: List[str]
    decided_by: str
    analysis_summary: str
    staged_actions: List[Dict[str, Any]]


def _rule_based_fallback() -> ScanState:
    """Same deterministic behavior the pre-agentic version used: run all
    three scanners in a fixed order, map known issue substrings to actions.
    Used only when the tool-calling investigation loop fails outright."""
    findings: List[Dict[str, Any]] = []
    findings.extend(scanners.scan_s3_security_issues())
    findings.extend(scanners.scan_iam_security_issues())
    findings.extend(scanners.scan_monitoring_issues())

    proposed = []
    for f in findings:
        for key, (action, risk, service) in _RULE_MAP.items():
            if key.lower() in f["issue"].lower():
                item = {
                    "resource_name": f["resource"], "service": service, "action": action,
                    "risk_level": risk, "reasoning": "Rule-based fallback analysis (local AI engine unreachable or returned an invalid response).",
                    "data_source": "mock" if f.get("_mock") else "live",
                }
                if f.get("access_key_id"):
                    item["access_key_id"] = f["access_key_id"]
                proposed.append(item)
                break

    return {
        "findings": findings,
        "proposed_actions": proposed,
        "tool_calls_log": ["fixed_order_fallback_scan"],
        "decided_by": "rule_fallback",
        "analysis_summary": "Rule-based fallback analysis (local AI engine unreachable or returned an invalid response).",
    }


def investigate_node(state: ScanState) -> ScanState:
    try:
        # WHAT: timeout is passed via client_kwargs, not a `timeout=` kwarg.
        # WHY: ChatOllama has no `timeout` field of its own -- passing it
        # directly is silently accepted and silently ignored (verified
        # against the installed version), which would have left Ollama
        # calls able to hang indefinitely. client_kwargs is forwarded to the
        # underlying ollama.Client(), which does respect it.
        llm = ChatOllama(model=OLLAMA_MODEL, base_url=OLLAMA_BASE_URL, temperature=0,
                          client_kwargs={"timeout": OLLAMA_TIMEOUT_SECONDS})
        llm_with_tools = llm.bind_tools(_TOOLS)

        messages = [SystemMessage(content=_SYSTEM_PROMPT),
                    HumanMessage(content="Begin the compliance investigation now.")]

        findings: List[Dict[str, Any]] = []
        proposed: List[Dict[str, Any]] = []
        tool_log: List[str] = []
        areas_checked = set()
        done = False

        for _ in range(MAX_AGENT_STEPS):
            response = llm_with_tools.invoke(messages)
            messages.append(response)

            if not getattr(response, "tool_calls", None):
                # WHAT: instead of treating a plain-text reply as "done",
                # nudge the model back onto tool-calling (small local models
                # often answer in prose once they have one result, instead
                # of chaining into the next tool call).
                # WHY: silently stopping here meant a real finding the model
                # had already seen (e.g. from get_iam_findings) could go
                # un-staged -- the loop isn't broken, the model just needs a
                # push to keep going, and MAX_AGENT_STEPS already bounds how
                # many pushes this can cost.
                if done:
                    break
                remaining = {"IAM", "S3", "Monitoring"} - areas_checked
                nudge = (
                    "You replied without calling a tool. Continue the investigation: "
                    + (f"call {', '.join('get_' + a.lower() + '_findings' for a in sorted(remaining))} next. "
                       if remaining else "")
                    + "If you have seen a real finding you have not staged yet, call stage_remediation "
                    + "for it now, with the exact resource name and a specific reasoning string. "
                    + "Only call finish_investigation once all three areas are checked and every "
                    + "real finding has been staged."
                )
                messages.append(HumanMessage(content=nudge))
                continue

            for call in response.tool_calls:
                name, args, call_id = call["name"], call.get("args", {}) or {}, call["id"]

                if name == "get_iam_findings":
                    result = scanners.scan_iam_security_issues()
                    findings.extend(result)
                    areas_checked.add("IAM")
                    tool_log.append("get_iam_findings")
                    messages.append(ToolMessage(content=json.dumps(result), tool_call_id=call_id))

                elif name == "get_s3_findings":
                    result = scanners.scan_s3_security_issues()
                    findings.extend(result)
                    areas_checked.add("S3")
                    tool_log.append("get_s3_findings")
                    messages.append(ToolMessage(content=json.dumps(result), tool_call_id=call_id))

                elif name == "get_monitoring_findings":
                    result = scanners.scan_monitoring_issues()
                    findings.extend(result)
                    areas_checked.add("Monitoring")
                    tool_log.append("get_monitoring_findings")
                    messages.append(ToolMessage(content=json.dumps(result), tool_call_id=call_id))

                elif name == "stage_remediation":
                    # WHAT: reject any action outside the whitelist right here,
                    # not just at /api/approve execution time.
                    # WHY: execute_remediation() already refuses an unknown
                    # action with a 400 -- but that guardrail firing only when
                    # a human clicks Approve means an invalid, hallucinated
                    # action (the model inventing "enable_macie", which was
                    # never one of the five allowed actions) sits in
                    # pending_actions looking like a real, approvable
                    # proposal until someone tries it and gets an error.
                    # Checking the whitelist at staging time means a bad
                    # proposal never reaches a human as if it were valid.
                    canon = remediation.canonical_action(args.get("action", ""))
                    if canon not in remediation.ALLOWED_ACTIONS:
                        tool_log.append(f"stage_remediation_REJECTED(invalid action: {args.get('action', '')!r})")
                        messages.append(ToolMessage(
                            content=(
                                f"'{args.get('action', '')}' is not an allowed action and was NOT staged. "
                                f"Only these actions exist: {json.dumps(remediation.ALLOWED_ACTIONS)}. "
                                "If this finding has no matching allowed action, do not stage anything for "
                                "it -- just note it and move on to the remaining areas."
                            ),
                            tool_call_id=call_id,
                        ))
                        continue
                    mock_resources = {f["resource"] for f in findings if f.get("_mock")}
                    item = {
                        "resource_name": args.get("resource_name", "unknown"),
                        "service": args.get("service", "unknown"),
                        "action": canon,
                        "risk_level": args.get("risk_level", "UNKNOWN"),
                        "reasoning": args.get("reasoning", ""),
                        "data_source": "mock" if args.get("resource_name") in mock_resources else "live",
                    }
                    if args.get("access_key_id"):
                        item["access_key_id"] = args["access_key_id"]
                    proposed.append(item)
                    tool_log.append(f"stage_remediation({item['action']} on {item['resource_name']})")
                    messages.append(ToolMessage(content=f"Staged: {item['action']} on {item['resource_name']}.", tool_call_id=call_id))

                elif name == "finish_investigation":
                    tool_log.append("finish_investigation")
                    messages.append(ToolMessage(content="Investigation marked complete.", tool_call_id=call_id))
                    done = True

            if done:
                break

        if not areas_checked:
            # The model never actually investigated anything real -- not
            # trustworthy enough to call this a successful agentic run.
            raise RuntimeError("Agent completed without checking any compliance area.")

        return {
            "findings": findings,
            "proposed_actions": proposed,
            "tool_calls_log": tool_log,
            "decided_by": "llama3_agentic",
            "analysis_summary": f"Agentic investigation checked {', '.join(sorted(areas_checked))} "
                                 f"and staged {len(proposed)} remediation(s) across {len(tool_log)} tool call(s).",
        }

    except Exception as e:
        log.warning("Agentic investigation failed, using rule-based fallback: %s", e)
        return _rule_based_fallback()


def stage_node(state: ScanState) -> ScanState:
    staged = []
    for item in state.get("proposed_actions", []):
        action = remediation.canonical_action(item["action"])
        verify_service, verify_keyword = _ACTION_VERIFY_KEYWORD.get(action, (item.get("service", "unknown"), ""))
        entry = {
            "action_id": str(uuid.uuid4()),
            "resource_name": item["resource_name"],
            "action": action,
            "risk_level": item.get("risk_level", "UNKNOWN"),
            "status": "PENDING_APPROVAL",
            "reasoning": item.get("reasoning", ""),
            "decided_by": state.get("decided_by", "unknown"),
            "data_source": item.get("data_source", "live"),
            "verify_service": verify_service,
            "verify_keyword": verify_keyword,
        }
        if item.get("access_key_id"):
            entry["access_key_id"] = item["access_key_id"]
        staged.append(entry)
    return {**state, "staged_actions": staged}  # type: ignore[typeddict-item]


_scan_graph_builder = StateGraph(ScanState)
_scan_graph_builder.add_node("investigate", investigate_node)
_scan_graph_builder.add_node("stage", stage_node)
_scan_graph_builder.set_entry_point("investigate")
_scan_graph_builder.add_edge("investigate", "stage")
_scan_graph_builder.add_edge("stage", END)
scan_graph = _scan_graph_builder.compile()


def run_scan() -> Dict[str, Any]:
    """Entry point used by POST /api/scan. Runs investigate -> stage and
    returns the final state (findings, staged_actions, analysis_summary, decided_by, tool_calls_log)."""
    result = scan_graph.invoke({"findings": [], "proposed_actions": [], "tool_calls_log": []})
    return result


# ---------------------------------------------------------------------------
# Remediate -> verify graph. Runs once per approved action, inside
# POST /api/approve. Only reached after a human has already approved --
# this graph never decides whether to act, only confirms what happened.
# ---------------------------------------------------------------------------
class RemediateState(TypedDict, total=False):
    task: Dict[str, Any]
    status: str
    message: str
    verification_status: str


def remediate_node(state: RemediateState) -> RemediateState:
    task = state["task"]
    from fastapi import HTTPException
    try:
        message = remediation.execute_remediation(task)
        return {**state, "status": "REMEDIATED", "message": message}
    except HTTPException:
        # An intentional guardrail error (e.g. "no access_key_id on this
        # action") -- a real validation failure, not an AWS connectivity
        # issue, so it should surface as an error, not a silent dry run.
        raise
    except Exception as e:
        # WHAT: broadened from the original's 3 specific boto3 exception
        # types to any exception. WHY: an unusual network failure (odd
        # proxy behavior, DNS hiccup, transient AWS outage) doesn't fit
        # those 3 types either, and the whole point of this project's
        # "demo-safe fallback" design is that remediation degrades
        # gracefully too, not just scanning.
        log.warning("AWS call failed during remediation, returning dry-run result: %s", e)
        return {
            **state,
            "status": "REMEDIATED (DRY RUN - AWS UNAVAILABLE)",
            "message": f"[DRY RUN] Would have applied '{task['action']}' to '{task['resource_name']}' "
                       f"-- AWS is not reachable/authorized in this environment: {e}",
        }


def verify_node(state: RemediateState) -> RemediateState:
    """The step that makes this agentic rather than fire-and-forget: after a
    real remediation, re-run the relevant scanner on the same resource to
    confirm the original finding is actually gone. Skipped for dry runs,
    since there's no real resource state to re-check."""
    if state["status"] != "REMEDIATED":
        return {**state, "verification_status": "SKIPPED_DRY_RUN"}

    task = state["task"]
    if task.get("data_source") == "mock":
        # Nothing real to re-check -- the "resource" only exists as a static
        # mock finding, so re-scanning it would always show the same data
        # regardless of the fix and misleadingly look like it failed.
        return {**state, "verification_status": "SKIPPED_MOCK_DATA_NO_REAL_RESOURCE"}

    service = task.get("verify_service")
    keyword = task.get("verify_keyword")
    if not service or not keyword:
        return {**state, "verification_status": "COULD_NOT_VERIFY_UNKNOWN_CHECK"}

    try:
        fixed = scanners.check_resource_now(service, task["resource_name"], keyword)
        if fixed is True:
            return {**state, "verification_status": "CONFIRMED_FIXED"}
        if fixed is False:
            return {**state, "verification_status": "STILL_PRESENT_RECHECK_NEEDED"}
        return {**state, "verification_status": "COULD_NOT_VERIFY"}
    except Exception as e:
        log.warning("Verification re-scan failed: %s", e)
        return {**state, "verification_status": "COULD_NOT_VERIFY"}


_remediate_graph_builder = StateGraph(RemediateState)
_remediate_graph_builder.add_node("remediate", remediate_node)
_remediate_graph_builder.add_node("verify", verify_node)
_remediate_graph_builder.set_entry_point("remediate")
_remediate_graph_builder.add_edge("remediate", "verify")
_remediate_graph_builder.add_edge("verify", END)
remediate_graph = _remediate_graph_builder.compile()


def run_remediation(task: Dict[str, Any]) -> Dict[str, Any]:
    """Entry point used by POST /api/approve, only after a human has
    already approved this specific action_id."""
    return remediate_graph.invoke({"task": task})
