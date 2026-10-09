# HIPAA/GDPR Compliance Guard — Sandbox Build

This is a working copy of the project, rebuilt for reliability ahead of the webinar.
It lives at `Desktop/PROJECTS/HIPAA-GDPR Compliance Guard on cloud`, right next to the
original `HIPAA-GDPR Compliance Guard` folder, which is untouched. No credentials were
copied into this folder.

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

## About "typesafe"

I read this as "validate everything so a bad AI response or bad input can't
silently corrupt behavior" (covered above with Pydantic). If you actually meant
a TypeScript frontend/dashboard on top of this API, that's a separate, bigger
piece of work — say the word and we can scope it, but it's not realistic to
also build well before tomorrow.

## About n8n

Added a `docker-compose.yml` that runs this API alongside n8n, and a
ready-to-import workflow (`compliance-scan-workflow.json`):

`Schedule (every 6h) or manual button -> POST /api/scan -> IF pending actions exist -> GET /api/pending -> notify`

Why it's worth showing in the webinar: right now the only way to run a scan or
see results is Swagger UI, which reads as "engineer's tool," not "product." n8n
gives you a visual canvas a non-technical audience can follow at a glance, and
it's where recurring scans, Slack/email alerts on findings, and (later) a
"click to approve" step belong — without writing more Python for each one.

**To run it:**
```
docker compose up --build
```
Then open `http://localhost:5678`, create a local n8n account on first run,
and import `compliance-scan-workflow.json` (Workflows -> Import from File).
Click the "Run Now (demo button)" node and press "Execute Workflow" to trigger
a live scan from the n8n canvas during the demo.

The "Notify Team" node is a placeholder (`NoOp`) — wire in n8n's Slack or
Email node there with your own credentials if you want an actual
notification to fire; I didn't want to guess at which channel/inbox to use.

## Running without Docker (what I tested with)

```
python -m venv venv
venv/bin/pip install -r requirements.txt      # Windows: venv\Scripts\pip
venv/bin/uvicorn main:app --reload --port 5000
```
Open `http://127.0.0.1:5000/docs`.

## Environment

Copy `.env.example` to `.env` and adjust. All fields have safe defaults; you
don't need Ollama or AWS creds running for the demo to produce output.
