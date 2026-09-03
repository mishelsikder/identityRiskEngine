# Identity Risk Engine

Backend for a claim-time identity risk pipeline: a user lands with a claim
("I'm a Stanford student"), an AI fraud engine scores them **before** any
evidence is collected, and only the ambiguous middle group is asked to
step up with evidence (email, document, identity) before a signed
Verifiable Credential is issued to their wallet. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full flow and design
rationale.

This is the **backend only**. The frontend is being designed separately in
FigJam and will be added to this repo alongside it.

## Stack

Python 3, built directly on [Starlette](https://www.starlette.io/) (the
ASGI framework FastAPI itself is built on) + [Pydantic](https://docs.pydantic.dev/)
for validation, [PyJWT](https://pyjwt.readthedocs.io/) + `cryptography` for
signing Verifiable Credentials as RS256 JWTs. No database — an in-memory
session store, swappable behind one interface. See
["Why Starlette, not FastAPI"](docs/ARCHITECTURE.md#why-starlette-not-fastapi)
for why, and how to swap to FastAPI directly if you have it available.

## Running it

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Then:

```bash
curl http://localhost:8000/health
```

## Running the tests

No `pytest` dependency required — the suite runs on the standard library's
`unittest`:

```bash
python -m unittest discover -s tests -v
```

26 tests cover the fraud engine's scoring thresholds, the evidence
consistency checker, credential issuance/verification, and full API flows
(fast-pass, fail, challenge→pass, challenge→deny, challenge→review).

## API reference

All requests/responses are JSON. Full request/response shapes are in
`app/models/`.

### `POST /claims`

Land with a claim. Runs the Stage 1 fraud gate (behavioral/device signals
only) immediately, before any evidence exists.

```json
{
  "claim_text": "I'm a Stanford student",
  "institution_name": "Stanford University",
  "device_signals": {
    "device_id": "device-fingerprint-abc",
    "ip_address": "203.0.113.4",
    "user_agent": "Mozilla/5.0 ...",
    "known_device": false,
    "vpn_or_datacenter_ip": false,
    "mouse_movement_entropy": 0.7,
    "time_on_page_ms": 4200
  }
}
```

Response — `verdict` is one of `PASS`, `FAIL`, `CHALLENGE`:

```json
{
  "session_id": "…",
  "verdict": "CHALLENGE",
  "risk_score": 34,
  "bot_score": 41,
  "breakdown": { "velocity_score": 0, "reuse_score": 0, "device_score": 0, "anomaly_score": 65 },
  "reasons": ["behavioral anomalies detected (65/100)"],
  "required_proofs": ["email", "document", "identity"],
  "credential": null
}
```

* `PASS` → `credential` is populated immediately, `assurance_level: "self_asserted"`.
* `FAIL` → denied, no credential, session ends.
* `CHALLENGE` → proceed to `POST /claims/{session_id}/evidence`.

### `POST /claims/{session_id}/evidence`

Only valid while the session is `AWAITING_EVIDENCE`. Submit whichever
proofs you have; all three are recommended for the strongest check.

```json
{
  "email_proof": { "email": "jane@stanford.edu" },
  "document_proof": {
    "full_name": "Jane Doe",
    "institution_name": "Stanford University",
    "student_id_number": "SU-12345",
    "issue_date": "2025-01-15",
    "expiry_date": "2027-06-30",
    "tamper_suspected": false
  },
  "identity_proof": { "method": "oauth", "full_name": "Jane Doe", "verified": true }
}
```

Response — `verdict` is one of `PASS`, `REVIEW`, `DENY`:

```json
{
  "session_id": "…",
  "verdict": "PASS",
  "risk_score": 12,
  "bot_score": 15,
  "consistency_score": 100,
  "breakdown": { "...": "..." },
  "reasons": ["all evidence fully consistent", "evidence fully consistent, no additional penalty"],
  "credential": { "assurance_level": "verified_evidence", "...": "..." }
}
```

### `GET /claims/{session_id}`

Debug/inspect a session's current state and scores.

### `GET /credentials/{credential_id}`

Fetch a previously issued credential by id.

### `POST /credentials/verify`

What "the other service" calls: independently verifies a credential's
signature, issuer, and expiry.

```json
{ "token": "eyJhbGciOi..." }
```

```json
{ "valid": true, "claims": { "sub": "...", "vc": { "credentialSubject": { "student": true, "institution": "Stanford University" } } } }
```

### `GET /.well-known/jwks.json`

The issuer's public key set, so any third party can verify credentials
without calling back into this service.

## Frontend integration notes (for the FigJam build)

* CORS is wide open (`*`) for local prototyping — tighten before deploying anywhere real.
* Land the user → `POST /claims` → branch UI on `verdict`.
* On `CHALLENGE`, `required_proofs` tells you which of the three proof forms to show.
* The `credential.token` is what goes "into the wallet" — for a demo, `localStorage`/a wallet mock is fine; it's a real signed JWT either way.
* `breakdown` + `reasons` on every response are meant to be shown in a debug/reviewer panel, not necessarily to the end user.
