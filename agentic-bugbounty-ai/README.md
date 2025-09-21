Agentic Bug Bounty AI (Safe Starter Repo)

IMPORTANT: Authorized, defensive testing only. This system does NOT implement exploit payloads or destructive testing. Always obtain explicit written authorization before any active tests on systems you do not own.

Overview

Agentic-bugbounty-ai is a secure, modular starter repository for an agentic web-application security testing system. It uses local LLMs via Ollama and optionally Anthropic Claude (through a redacting audit gateway) to orchestrate safe, non-destructive reconnaissance, triage, and reporting.

Core safety features

- Signed authorization manifests required for any scan (and specifically enforced before any active test).
- Default passive-only mode. Active tests require per-job active_consent flag AND manual approval via an API/CLI toggle.
- Rate limiting (global and per-target), with backoff and kill-switch endpoints.
- Evidence logging with immutable, append-only JSONL and HMAC signature. Optional encryption (Fernet) and key rotation.
- External model calls must go through the Claude gateway which redacts secrets and audits requests/responses.
- No exploit payloads or destructive tests included. Only non-destructive stubs and safe checks.

Architecture (ASCII)

                    +------------------------------+
                    |            Frontend          |
                    |  React single page (Form)    |
                    +---------------+--------------+
                                    |
                                    v
                   +----------------+----------------+
                   |            FastAPI Backend      |
                   |  - Auth Manifest Verification   |
                   |  - Policy Engine & Rate Limits  |
                   |  - Orchestrator & Job Queue     |
                   |  - Evidence Storage (append)    |
                   |  - Reports Generator            |
                   |  - Ollama & Claude Gateway      |
                   +--------+---------------+--------+
                            |               |
                            |               |
                            v               v
                  +---------+----+   +------+---------+
                  | Manager/Queue|   |   Claude GW    |
                  | (SyncManager)|   | (redact+audit) |
                  +------+-------+   +-----------------+
                         |
                         v
                 +-------+----------------------------+
                 |         Worker Container           |
                 |  - Stateless plugin executor       |
                 |  - Safe plugins (crawler, headers) |
                 +------------------------------------+

Repo layout

- backend: FastAPI app, orchestrator, workers, plugins, storage, and integrations
- frontend: Minimal React single file UI
- scripts: Authorization manifest tools
- docs: Prompts, architecture, safe usage
- tests: Unit tests for core safety and integrations

Quickstart (Docker)

1) Prerequisites: Docker and docker-compose.
2) Build & run services:

   docker-compose up --build

3) Generate a sample signed manifest (dev only):

   python ./scripts/sign_manifest.py gen-key --out ./dev_keys
   python ./scripts/sign_manifest.py sign --key ./dev_keys/private.pem --manifest ./examples/example_scan_request.json --out ./examples/signed_manifest.json

4) Start a passive scan (sample):

   curl -s -X POST http://localhost:8000/api/v1/scan \
     -H 'Content-Type: application/json' \
     -d @./examples/example_scan_request.json | jq

5) Approve active mode (example; only necessary if the job has mode=active and active_consent=true):

   curl -s -X POST http://localhost:8000/api/v1/scan/<job_id>/approve-active \
     -H 'X-Operator-Token: dev-operator-token' \
     -H 'Content-Type: application/json' \
     -d @./examples/signed_manifest.json | jq

6) Kill switch:

   curl -s -X POST http://localhost:8000/api/v1/kill/<job_id> -H 'X-Operator-Token: dev-operator-token'

Environment variables

- OPERATOR_TOKEN: Token required to approve active tests and kill jobs (default: dev-operator-token)
- AUTH_PUBLIC_KEY_BASE64: Base64 Ed25519 public key for manifest verification
- EVIDENCE_HMAC_KEY: Secret for evidence HMAC signing (required)
- EVIDENCE_ENCRYPTION_KEY: Optional Fernet key for evidence encryption (generate with cryptography.Fernet.generate_key)
- QUEUE_MANAGER_HOST, QUEUE_MANAGER_PORT, QUEUE_MANAGER_AUTHKEY: Queue manager configuration (worker connects to backend)
- CLAUDE_API_KEY: Optional; if set, the Claude gateway can call Anthropic API. Raw API key is never logged.

Ollama setup

- Ensure Ollama is installed locally and models downloaded. The backend lists local models via GET /api/v1/models. If Ollama is absent, a simulator mode is used with stub data for development.

Claude gateway

- To enable real calls, export CLAUDE_API_KEY. Requests and responses are redacted and audited. Without a key, the gateway returns safe stubbed responses.

Legal & safety checklist (must read)

- You confirm you have explicit, written authorization to test the target(s).
- You understand that default mode is passive-only; enabling active tests requires manifest-specified consent plus operator approval.
- You will not attempt exploitation or use destructive payloads. This system does not provide them.
- You agree to respect rate limits and halt tests upon request of the asset owner.

Developer guide

- Extend with new plugins by creating a module under backend/app/plugins/ with:
  - metadata = {"name": "plugin_name", "safe_default": True, "required_manifest_scopes": ["web"], "http_methods": ["GET"]}
  - a run(context) function that returns structured findings. Only non-destructive logic permitted.
- To integrate Redis/RabbitMQ later, replace the SyncManager queue in orchestrator and update worker to consume from that backend.
- To add ZAP/Burp, wrap their safe modes in plugins and ensure policy_engine enforces allowed HTTP methods and scopes.

Run backend locally (without Docker)

   cd backend
   python -m venv .venv && source .venv/bin/activate
   pip install -r requirements.txt
   export EVIDENCE_HMAC_KEY="dev-secret-please-change"
   export AUTH_PUBLIC_KEY_BASE64="<base64_ed25519_public_key>"
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

Non-actionable reminders

- This repo is ONLY for authorized, defensive testing.
- The system does NOT implement or contain exploit payloads; it is intended for discovery, triage, and safe active-check orchestration.
- Always obtain explicit written authorization before running active tests on systems you do not own.

