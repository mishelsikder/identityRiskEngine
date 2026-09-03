"""Evidence consistency checker.

Checks the three proofs collected on the CHALLENGE path against each other
and against the original claim:

  * names match across document_proof and identity_proof
  * institution exists in the registry
  * email domain matches the claimed institution
  * dates on the document are plausible (not expired, not absurdly old/future)
  * document tamper flag (simulated model output)

Returns a 0-100 consistency_score (100 = fully consistent) plus a
hard_deny flag for conditions severe enough to force a DENY regardless of
score (a detected forgery shouldn't be something a good score elsewhere
can outweigh).
"""
from dataclasses import dataclass, field
from datetime import date
from typing import List

from app.models.claim import ClaimRequest
from app.models.evidence import EvidenceSubmission
from app.services import institution_registry

MAX_DOCUMENT_AGE_YEARS = 10
MAX_EXPIRY_HORIZON_YEARS = 6


@dataclass
class EvidenceCheckResult:
    consistency_score: int
    hard_deny: bool
    reasons: List[str] = field(default_factory=list)


def _normalize_name(name: str) -> str:
    return " ".join(name.strip().lower().split())


def check_evidence(claim: ClaimRequest, evidence: EvidenceSubmission) -> EvidenceCheckResult:
    reasons: List[str] = []
    penalty = 0
    hard_deny = False

    # -- required proofs present? ------------------------------------
    missing = []
    if evidence.email_proof is None:
        missing.append("email")
    if evidence.document_proof is None:
        missing.append("document")
    if evidence.identity_proof is None:
        missing.append("identity")
    if missing:
        penalty += 15 * len(missing)
        reasons.append(f"missing proof(s): {', '.join(missing)}")

    # -- institution exists? -------------------------------------------
    institution = institution_registry.lookup(claim.institution_name)
    if institution is None:
        penalty += 20
        reasons.append(
            f"institution '{claim.institution_name}' not found in registry "
            "(falling back to generic .edu check where applicable)"
        )

    # -- email domain matches institution? ------------------------------
    if evidence.email_proof is not None:
        if institution_registry.email_domain_matches(claim.institution_name, evidence.email_proof.email):
            reasons.append("email domain matches claimed institution")
        else:
            penalty += 25
            reasons.append("email domain does NOT match claimed institution")

    # -- names match across document + identity proof? -------------------
    if evidence.document_proof is not None and evidence.identity_proof is not None:
        doc_name = _normalize_name(evidence.document_proof.full_name)
        id_name = _normalize_name(evidence.identity_proof.full_name)
        if doc_name == id_name:
            reasons.append("document and identity proof names match")
        else:
            penalty += 30
            reasons.append("document and identity proof names DO NOT match")

    # -- identity proof itself verified? ---------------------------------
    if evidence.identity_proof is not None and not evidence.identity_proof.verified:
        penalty += 30
        reasons.append("identity proof (OAuth/passkey) ceremony did not verify")

    # -- document institution matches claim? ------------------------------
    if evidence.document_proof is not None:
        if _normalize_name(evidence.document_proof.institution_name) != _normalize_name(
            claim.institution_name
        ):
            penalty += 20
            reasons.append("document institution does not match claimed institution")

        # -- dates plausible? ------------------------------------------------
        today = date.today()
        issue = evidence.document_proof.issue_date
        expiry = evidence.document_proof.expiry_date
        if expiry < today:
            penalty += 25
            reasons.append("document has already expired")
        if issue > today:
            penalty += 25
            reasons.append("document issue date is in the future")
        if (today.year - issue.year) > MAX_DOCUMENT_AGE_YEARS:
            penalty += 10
            reasons.append("document issue date implausibly old")
        if (expiry.year - today.year) > MAX_EXPIRY_HORIZON_YEARS:
            penalty += 10
            reasons.append("document expiry date implausibly far in the future")
        if expiry <= issue:
            penalty += 15
            reasons.append("document expiry date is not after its issue date")

        # -- tamper flag -------------------------------------------------
        if evidence.document_proof.tamper_suspected:
            hard_deny = True
            reasons.append("document tampering suspected by forensic check")

    consistency_score = max(0, 100 - penalty)
    if not reasons:
        reasons.append("all evidence fully consistent")

    return EvidenceCheckResult(
        consistency_score=consistency_score, hard_deny=hard_deny, reasons=reasons
    )
