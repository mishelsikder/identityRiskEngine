from typing import Any, Dict, Optional

from pydantic import BaseModel


class VerifiableCredential(BaseModel):
    """The signed, wallet-ready output of a PASS verdict."""

    credential_id: str
    token: str  # signed JWT — this is what actually goes into the user's wallet
    issuer: str
    subject_id: str
    institution: str
    student: bool
    assurance_level: str
    risk_score: int
    bot_score: int
    issued_at: str
    expires_at: str


class CredentialVerifyRequest(BaseModel):
    token: str


class CredentialVerifyResponse(BaseModel):
    valid: bool
    reason: Optional[str] = None
    claims: Optional[Dict[str, Any]] = None
