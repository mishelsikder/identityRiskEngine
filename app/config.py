"""Central configuration and tunable thresholds for the identity risk engine.

Everything here is intentionally a plain constant (not env-driven secrets)
because this build targets a simulated/rule-based fidelity level: no external
provider keys are required to run the service end to end. Swap in
environment-variable loading (e.g. pydantic-settings) if/when this moves
towards real provider integrations.
"""
from pathlib import Path

# ---------------------------------------------------------------------------
# Issuer / credential settings
# ---------------------------------------------------------------------------
ISSUER_NAME = "identity-risk-engine"
ISSUER_URL = "https://issuer.identity-risk-engine.local/"
KEYS_DIR = Path(__file__).resolve().parent.parent / "keys"
PRIVATE_KEY_PATH = KEYS_DIR / "issuer_private.pem"
PUBLIC_KEY_PATH = KEYS_DIR / "issuer_public.pem"
JWT_ALGORITHM = "RS256"

CREDENTIAL_EXPIRY_DAYS_SELF_ASSERTED = 30
CREDENTIAL_EXPIRY_DAYS_VERIFIED = 365 * 2  # ~2 years, matches "Expires = 2027" style claims

# ---------------------------------------------------------------------------
# Stage 1 — landing / pre-evidence fraud gate thresholds
# Verdict in {PASS, FAIL, CHALLENGE}
# ---------------------------------------------------------------------------
STAGE1_PASS_MAX_RISK = 15
STAGE1_PASS_MAX_BOT = 20
STAGE1_FAIL_MIN_RISK = 85
STAGE1_FAIL_MIN_BOT = 80

# ---------------------------------------------------------------------------
# Stage 2 — post-evidence fraud + consistency gate thresholds
# Verdict in {PASS, REVIEW, DENY}
# ---------------------------------------------------------------------------
STAGE2_DENY_MIN_RISK = 70
STAGE2_REVIEW_MIN_RISK = 40

# Velocity / reuse windows (in-memory, simulated abuse signals)
VELOCITY_WINDOW_SECONDS = 60 * 10  # 10 minutes
VELOCITY_HIGH_COUNT = 3            # >=3 landings from same device/IP in window looks scripted
REUSE_HIGH_DISTINCT_INSTITUTIONS = 2  # same device claiming >=2 different institutions is suspicious

REQUIRED_PROOFS_ON_CHALLENGE = ["email", "document", "identity"]
