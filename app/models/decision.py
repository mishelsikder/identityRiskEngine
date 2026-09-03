from typing import List, Optional

from pydantic import BaseModel

from app.models.credential import VerifiableCredential
from app.models.verdict import Verdict


class RiskScoreBreakdown(BaseModel):
    """Sub-scores that rolled up into the final risk_score / bot_score.

    Exposed so the frontend (or a human reviewer) can show *why* a verdict
    happened instead of just the number.
    """

    velocity_score: int
    reuse_score: int
    device_score: int
    anomaly_score: int
    consistency_penalty: Optional[int] = None  # only present post-evidence


class ClaimLandingResponse(BaseModel):
    """Response to POST /claims — the Stage 1 fraud-gate result."""

    session_id: str
    verdict: Verdict
    risk_score: int
    bot_score: int
    breakdown: RiskScoreBreakdown
    reasons: List[str]
    required_proofs: List[str] = []
    credential: Optional[VerifiableCredential] = None


class EvidenceDecisionResponse(BaseModel):
    """Response to POST /claims/{session_id}/evidence — the Stage 2 result."""

    session_id: str
    verdict: Verdict
    risk_score: int
    bot_score: int
    consistency_score: int
    breakdown: RiskScoreBreakdown
    reasons: List[str]
    credential: Optional[VerifiableCredential] = None
