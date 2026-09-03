import unittest
from datetime import date, timedelta

from app.engine.evidence_checker import check_evidence
from app.models.claim import ClaimRequest, DeviceSignals
from app.models.evidence import DocumentProof, EmailProof, EvidenceSubmission, IdentityProof


def _claim() -> ClaimRequest:
    return ClaimRequest(
        claim_text="I'm a Stanford student",
        institution_name="Stanford University",
        device_signals=DeviceSignals(device_id="d1", ip_address="1.1.1.1"),
    )


def _consistent_evidence() -> EvidenceSubmission:
    today = date.today()
    return EvidenceSubmission(
        email_proof=EmailProof(email="jane@stanford.edu"),
        document_proof=DocumentProof(
            full_name="Jane Doe",
            institution_name="Stanford University",
            student_id_number="12345",
            issue_date=today - timedelta(days=100),
            expiry_date=today + timedelta(days=365),
        ),
        identity_proof=IdentityProof(method="oauth", full_name="Jane Doe", verified=True),
    )


class TestEvidenceChecker(unittest.TestCase):
    def test_fully_consistent_evidence_scores_high(self):
        result = check_evidence(_claim(), _consistent_evidence())
        self.assertGreaterEqual(result.consistency_score, 95)
        self.assertFalse(result.hard_deny)

    def test_name_mismatch_penalized(self):
        evidence = _consistent_evidence()
        evidence.identity_proof.full_name = "John Smith"
        result = check_evidence(_claim(), evidence)
        self.assertLess(result.consistency_score, 95)
        self.assertIn(
            "document and identity proof names DO NOT match", result.reasons
        )

    def test_unknown_institution_penalized(self):
        claim = ClaimRequest(
            claim_text="I'm a student",
            institution_name="Totally Unknown University",
            device_signals=DeviceSignals(device_id="d1", ip_address="1.1.1.1"),
        )
        evidence = _consistent_evidence()
        evidence.document_proof.institution_name = "Totally Unknown University"
        evidence.email_proof = EmailProof(email="jane@totallyunknown.edu")
        result = check_evidence(claim, evidence)
        self.assertTrue(
            any("not found in registry" in r for r in result.reasons)
        )

    def test_expired_document_penalized(self):
        evidence = _consistent_evidence()
        evidence.document_proof.expiry_date = date.today() - timedelta(days=1)
        result = check_evidence(_claim(), evidence)
        self.assertIn("document has already expired", result.reasons)

    def test_tamper_flag_forces_hard_deny(self):
        evidence = _consistent_evidence()
        evidence.document_proof.tamper_suspected = True
        result = check_evidence(_claim(), evidence)
        self.assertTrue(result.hard_deny)

    def test_missing_proofs_penalized(self):
        evidence = EvidenceSubmission()
        result = check_evidence(_claim(), evidence)
        self.assertLess(result.consistency_score, 100)


if __name__ == "__main__":
    unittest.main()
