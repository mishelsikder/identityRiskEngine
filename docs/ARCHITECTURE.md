# Architecture

## Flow

This is the original whiteboard design, updated per the actual build: the
fraud engine now runs **twice** — once immediately on landing (before any
evidence exists), and again after evidence is collected on the CHALLENGE
path.

```
                         CLAIM
              "I'm a Stanford student"
                          │
                          ▼
              ┌───────────────────────┐
              │   AI FRAUD ENGINE      │   Stage 1 — behavioral/device
              │   (Stage 1, pre-evidence)   signals only: velocity, reuse,
              └───────────┬───────────┘   device, anomalies
                          │
            ┌─────────────┼──────────────┐
            ▼             ▼              ▼
          PASS          FAIL         CHALLENGE
            │             │              │
            │             │              ▼
            │             │     ┌──────────────────┐
            │             │     │  Trust Engine     │
            │             │     └────────┬──────────┘
            │             │      ┌───────┼────────┐
            │             │      ▼       ▼        ▼
            │             │  Email    Document  Identity
            │             │  proof    proof     proof
            │             │  .edu     Student ID OAuth/passkey
            │             │      └───────┼────────┘
            │             │              ▼
            │             │     ┌──────────────────┐
            │             │     │  AI FRAUD ENGINE   │  Stage 2 — folds
            │             │     │  (Stage 2, +evidence)  Stage 1 signals +
            │             │     └────────┬──────────┘  evidence consistency
            │             │      ┌───────┴────────┐    (names match? institution
            │             │      ▼                ▼    exists? dates plausible?
            │             │    PASS         REVIEW/DENY document tampering?)
            │             │      │                │
            │           (denied) │            (held / denied)
            │                    │
            ▼                    ▼
     ┌─────────────────────────────────┐
     │      Verifiable Credential       │
     │  Student = TRUE                  │
     │  Institution = X                 │
     │  Expires = 2027 (or 30d if       │
     │    self-asserted)                │
     │  Signed by issuer                │
     └────────────────┬─────────────────┘
                       ▼
                 User's wallet
                       │
                       ▼
                 Other service
                 (verifies via GET /.well-known/jwks.json
                  + POST /credentials/verify)
```

### Why front-load the fraud engine?

Running cheap behavioral/device scoring *before* asking for any evidence
means: obviously-fine users get a credential with zero friction (`PASS` →
straight to a `self_asserted`-assurance credential), obviously-bot/abusive
traffic gets cut off before it ever sees the evidence-collection UI
(`FAIL`), and only the genuinely ambiguous middle pays the friction cost of
uploading a document and doing an OAuth/passkey ceremony (`CHALLENGE`).
This is the same shape as step-up authentication in fraud-prevention
systems generally (frictionless-by-default, friction only when warranted).

### Two assurance levels

A credential issued straight off Stage 1 (`PASS`, no evidence collected)
is marked `assurance_level: "self_asserted"` and expires quickly (30 days
by default). A credential issued after Stage 2 evidence checking
(`assurance_level: "verified_evidence"`) expires much further out (~2
years, matching the "Expires = 2027" style claim in the original design).
A relying party ("other service") can decide how much to trust each level
differently — see `credentialSubject.assurance_level` in the JWT.

### Risk score vs. bot score

Both are 0–100 and returned on every response, per the requested design
change. They're built from the same four sub-signals but weighted
differently:

* **`risk_score`** emphasizes *fraud/abuse-farming* signals — velocity
  (many landings from the same device/IP in a short window) and reuse
  (the same device claiming multiple distinct institutions).
* **`bot_score`** emphasizes *automation* signals — device fingerprint
  quality and behavioral anomalies (datacenter/VPN IP, near-zero mouse
  entropy, near-instant submission).

See `app/engine/fraud_engine.py` for the exact weights and
`app/config.py` for the gating thresholds — both are simple constants,
deliberately easy to tune.

### State machine

```
LANDED ──┬─→ PASSED_INITIAL ──────────────┐
         ├─→ FAILED_INITIAL (terminal)     │
         └─→ AWAITING_EVIDENCE             │
                  │                        │
                  ├─→ PASSED_FINAL ───┐    │
                  ├─→ REVIEW_PENDING   │    │
                  └─→ DENIED_FINAL     │    │
                                       ▼    ▼
                              CREDENTIAL_ISSUED
```

Enforced in `app/state_machine.py` so an invalid transition (e.g.
submitting evidence twice against the same session) raises instead of
silently corrupting state — surfaced as an HTTP 409 from the router.

## Simulated vs. real

This build is intentionally **rule-based/simulated fidelity** — no
external provider keys required, runs standalone. Every place a real
integration would plug in is a single, small, independently-testable
function:

| Simulated here | Real equivalent |
|---|---|
| `app/engine/fraud_engine.py` sub-scorers (velocity/reuse/device/anomaly) | A trained fraud/bot-detection model, device-reputation API, IP intelligence provider |
| `app/services/institution_registry.py` mock dict | IPEDS / National Student Clearinghouse / a partnered SSO federation lookup |
| `DocumentProof.tamper_suspected` (caller-supplied flag) | A real document-forensics / OCR tamper-detection model's output |
| `IdentityProof.verified` (caller-supplied flag) | An actual OAuth/passkey ceremony's result |
| In-memory `SessionStore` | Redis/Postgres, so state survives a restart and scales past one process |
| Locally-generated/cached RSA keypair | KMS/HSM-backed signing key |

None of the business logic (`app/engine/`, `app/models/`, the routers)
needs to change to swap any of these — only the implementation behind the
interface does.

## Why Starlette, not FastAPI

This was built and tested in an environment without PyPI network access,
where `fastapi` (and a couple of its usual optional deps) couldn't be
installed but `starlette`, `pydantic`, `uvicorn`, `PyJWT`, and
`cryptography` already were. Starlette is FastAPI's own foundation, so the
resulting API is functionally identical — same routes, same JSON in/out,
same status codes. `app/http.py` re-implements the two things FastAPI
would otherwise give routers for free (pydantic body validation, and
structured error responses via a small `ApiError` exception).

If you have FastAPI available, swapping is a one-file change: replace
`app/main.py`'s `Starlette(...)` app + manual `Route(...)` list with a
`FastAPI()` app and `@app.post(...)` decorators wrapping the same handler
functions in `app/routers/*.py` (each already takes/returns the right
pydantic models — only the function signature's request-parsing line
would change from `claim = await parse_body(request, ClaimRequest)` to a
plain typed parameter). You'd also get automatic OpenAPI/Swagger docs at
`/docs` for free, which the FigJam-to-frontend handoff may find useful.
