# HIPAA/GDPR Compliance Guard

An autonomous AWS compliance **agent** with a human-approval gate: it investigates IAM/S3/
CloudTrail for HIPAA/GDPR-style issues, decides for itself which checks to run and what to do
about each finding, stages proposed fixes for a person to approve, and then -- after a fix is
applied -- re-checks the resource itself to confirm the fix actually worked.

Live at `github.com/syedsaliq7866/compliance-scan`. The local working copy lives at
`Desktop/PROJECTS/HIPAA-GDPR Compliance Guard on cloud`, next to the original pre-rewrite
project folder, which is left untouched. No credentials are committed to this repo.

## The agentic engine (`agent_graph.py`, built on LangGraph)

The AI's job used to be one call per scan: "here are the findings, return a JSON risk
classification." That's a classifier, not an agent. `agent_graph.py` replaces it with two
small LangGraph graphs:

- **investigate -> stage** (runs inside `POST /api/scan`): the model is given the scanners
  themselves as tools (`get_iam_findings`, `get_s3_findings`, `get_monitoring_findings`) plus
  a `stage_remediation` tool and a `finish_investigation` tool. It decides which areas to
  check, in what order, and proposes a remediation -- with its own written reasoning -- for
  each real finding, calling `finish_investigation` when it's done. Every proposed fix is
  still filtered through the same `ALLOWED_ACTIONS` whitelist before it can ever be staged.
- **remediate -> verify** (runs inside `POST /api/approve`, only after a human has already
  approved one specific action): applies the fix, then re-runs the relevant scanner against
  the *same resource* to confirm the original finding is actually gone. This is the step that
  makes it agentic rather than fire-and-forget -- it checks its own work.

Every `/api/scan` response now includes `decided_by` (`"llama3_agentic"` if the model's
tool-calling loop ran successfully, `"rule_fallback"` if it didn't) and `tool_calls` (the
actual sequence of tools the agent called), so you can point at the response during a demo
and show which path produced a given decision rather than just asserting it. Every
`/api/approve` response includes `verification_status`: `CONFIRMED_FIXED`,
`STILL_PRESENT_RECHECK_NEEDED`, `SKIPPED_DRY_RUN` (no real AWS call was made), or
`SKIPPED_MOCK_DATA_NO_REAL_RESOURCE` (the finding came from mock fallback data, so there's
no real resource to re-check).

**Why it still falls back to the old deterministic rule-based mapping:** local 8B models are
noticeably less reliable at tool-calling than hosted frontier models. If the investigation
loop fails for any reason -- Ollama down, a timeout, a malformed tool call, the model never
calling a single real tool -- `investigate_node` catches it and falls back to running all
three scanners in a fixed order and mapping known issue substrings to actions, exactly like
the pre-agentic version did. A flaky local model degrades the demo from "agentic" to "still
correct," never to "broken."

## What changed from the original, and why

1. **Type-safe AI output.** Every shape crossing a boundary (the local AI's
   JSON response, the API's request/response bodies) now has a Pydantic model
   (`AIDecision`, `AIAction`, `Finding`, `PendingAction`). The original code
   trusted the AI's raw JSON and indexed into it directly, which threw an
   unhandled 500 if the model returned something malformed. Now a bad response
   is caught and handled.

2. **Demo-safe fallbacks everywhere.** If AWS credentials aren't configured,
   or a call fails mid-scan, each scanner falls back to realistic mock
   findings instead of crashing or silently returning nothing. If Ollama isn't
   running or times out (8s), a deterministic rule-based mapper takes over so
   `/api/scan` still produces a usable result. This is the main thing that
   makes the demo resilient — it can't go down because a laptop's Wi-Fi hiccups
   or Ollama hasn't finished loading the model.

3. **Two correctness fixes:**
   - `enable_mfa` was renamed `quarantine_user_pending_mfa` (old name kept as
     an alias so nothing breaks) because approving it doesn't enable MFA at
     all — it attaches a deny-all policy. The new name says what it does.
   - `deactivate_key` (now `deactivate_stale_key`) deactivates only the
     specific key ID the scan flagged as stale, not every key the user has.

4. **`storage_compliance.py` and `monitoring_compliance.py` are wired in.**
   They used to be standalone scripts nothing called. `/api/scan` now also
   checks S3 encryption/versioning and CloudTrail/Macie status, so the scan
   actually covers what the project name promises. `audit.py`,
   `iam_compliance.py`, and `remediate.py` are left as-is in this folder but
   aren't called by the API — they're redundant with what's now in `main.py`.
   Safe to delete once you've confirmed you don't need them as standalone CLI
   tools.

5. **Optional API key.** Set `API_KEY` in `.env` to require an `X-API-Key`
   header on every endpoint. Left blank by default so the demo doesn't need
   extra setup, but it's there for whenever this goes beyond a sandbox.

6. **CI no longer auto-remediates.** The repo's GitHub Actions workflow used
   to run `remediate.py` automatically on every push to `main` — meaning it
   could change real AWS resources with nobody looking at the findings first,
   which directly contradicted the human-approval design above. The workflow
   (`.github/workflows/compliance.yml`) now only runs when manually triggered
   from the Actions tab, and only builds/checks the container — it never calls
   `remediate.py`. The one and only path to a real AWS change is a human
   hitting `/api/approve`.

## About "typesafe"

Read as "validate everything so a bad AI response or bad input can't
silently corrupt behavior" (covered above with Pydantic). A TypeScript
frontend/dashboard on top of this API is a separate, bigger piece of work
that hasn't been started.

## About n8n

A `docker-compose.yml` runs this API alongside n8n, with a ready-to-import
workflow (`workflows/compliance-scan-workflow.json`):

`Schedule (every 6h) or manual button -> POST /api/scan -> IF pending actions exist -> GET /api/pending -> notify`

Right now the only way to run a scan or see results without n8n is Swagger UI,
which reads as "engineer's tool," not "product." n8n gives a visual canvas a
non-technical audience can follow at a glance, and it's where recurring scans
and alerts on findings live without writing more Python for each one.

**To run it:**
```
docker compose up --build
```
Then open `http://localhost:5678`, create a local n8n account on first run,
and import `workflows/compliance-scan-workflow.json` (Workflows -> Import from
File). Click the "Run Now (demo button)" node and press "Execute Workflow" to
trigger a live scan from the n8n canvas.

The "Notify Team" node started as a placeholder (`NoOp`). To wire it up for
real: delete that node, add n8n's built-in **Send Email** node in its place
(reconnect it so `Get Pending Actions -> Send Email`), and create an SMTP
credential for it (host, port 587, your email address, and an app password —
not your account password — if using Gmail or similar). The credential lives
inside n8n's own encrypted credential store, never in this repo or `.env`.

## Running without Docker (what was tested with)

```
python -m venv venv
venv/bin/pip install -r requirements.txt      # Windows: venv\Scripts\pip
venv/bin/uvicorn main:app --reload --port 5000
```
Open `http://127.0.0.1:5000/docs`.

## Environment

Copy `.env.example` to `.env` and adjust. All fields have safe defaults; you
don't need Ollama or AWS creds running for the demo to produce output.
