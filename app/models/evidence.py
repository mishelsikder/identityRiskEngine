import re
from datetime import date
from typing import Optional

from pydantic import BaseModel, Field, field_validator

# Deliberately not using pydantic's EmailStr here: that type requires the
# optional `email-validator` package, which isn't available in every
# deployment environment this backend might run in. A pragmatic
# format-only regex check is sufficient for this simulated fidelity level.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class EmailProof(BaseModel):
    """.edu-domain email ownership proof."""

    email: str

    @field_validator("email")
    @classmethod
    def _valid_email_format(cls, v: str) -> str:
        if not _EMAIL_RE.match(v):
            raise ValueError("not a valid email address")
        return v


class DocumentProof(BaseModel):
    """Student ID / enrollment document proof.

    ``tamper_suspected`` stands in for what a real document-forensics /
    OCR model would output (font inconsistency, edit artifacts, metadata
    mismatches, etc.) — see docs/ARCHITECTURE.md for the swap-in point.
    """

    full_name: str
    institution_name: str
    student_id_number: str
    issue_date: date
    expiry_date: date
    tamper_suspected: bool = Field(
        default=False,
        description="Simulated output of a document-forensics/tamper-detection model",
    )


class IdentityProof(BaseModel):
    """OAuth / passkey backed identity assertion."""

    method: str = Field(..., description="'oauth' or 'passkey'")
    full_name: str
    verified: bool = Field(
        default=True, description="Whether the OAuth/passkey ceremony itself succeeded"
    )


class EvidenceSubmission(BaseModel):
    """Payload for the CHALLENGE follow-up step. At least one proof is expected;
    in practice the frontend should collect all three named in
    REQUIRED_PROOFS_ON_CHALLENGE for the strongest consistency check."""

    email_proof: Optional[EmailProof] = None
    document_proof: Optional[DocumentProof] = None
    identity_proof: Optional[IdentityProof] = None
