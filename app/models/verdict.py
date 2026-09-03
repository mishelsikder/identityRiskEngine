from enum import Enum


class Verdict(str, Enum):
    """Unified verdict space across both fraud-engine passes.

    Stage 1 (landing, pre-evidence) only ever returns PASS / FAIL / CHALLENGE.
    Stage 2 (post-evidence) only ever returns PASS / REVIEW / DENY.
    Keeping one enum avoids duplicated near-identical types across the API.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    CHALLENGE = "CHALLENGE"
    REVIEW = "REVIEW"
    DENY = "DENY"


class AssuranceLevel(str, Enum):
    """How much evidence backs the credential's claim.

    Mirrors real-world identity assurance level concepts (e.g. NIST IAL1/IAL2):
    a credential issued straight off the Stage 1 fast-path carries a lower
    assurance level than one issued after document + identity evidence was
    collected and checked for consistency.
    """

    SELF_ASSERTED = "self_asserted"       # Stage 1 frictionless pass, no documentary evidence
    VERIFIED_EVIDENCE = "verified_evidence"  # Stage 2 pass, evidence collected + checked
