import unittest
from datetime import date, timedelta

from starlette.testclient import TestClient

from app.main import app


def _device(**overrides):
    base = dict(
        device_id="d-flow-1",
        ip_address="9.9.9.9",
        user_agent="Mozilla/5.0",
        known_device=False,
        vpn_or_datacenter_ip=False,
        mouse_movement_entropy=0.7,
        time_on_page_ms=4000,
    )
    base.update(overrides)
    return base


class TestApiFlow(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "ok")

    def test_jwks_endpoint(self):
        resp = self.client.get("/.well-known/jwks.json")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("keys", resp.json())

    def test_fast_pass_issues_credential_immediately(self):
        resp = self.client.post(
            "/claims",
            json={
                "claim_text": "I'm a Stanford student",
                "institution_name": "Stanford University",
                "device_signals": _device(device_id="d-pass-1", ip_address="10.1.0.1", known_device=True),
            },
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["verdict"], "PASS")
        self.assertIsNotNone(body["credential"])
        self.assertEqual(body["credential"]["assurance_level"], "self_asserted")

        # third-party verification of the credential
        verify_resp = self.client.post(
            "/credentials/verify", json={"token": body["credential"]["token"]}
        )
        self.assertTrue(verify_resp.json()["valid"])

    def test_fail_denies_immediately_with_no_credential(self):
        resp = self.client.post(
            "/claims",
            json={
                "claim_text": "I'm a Stanford student",
                "institution_name": "Stanford University",
                "device_signals": _device(
                    device_id="",
                    ip_address="10.1.0.2",
                    vpn_or_datacenter_ip=True,
                    mouse_movement_entropy=0.01,
                    time_on_page_ms=20,
                    user_agent="",
                ),
            },
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["verdict"], "FAIL")
        self.assertIsNone(body["credential"])

    def test_challenge_then_pass_with_consistent_evidence(self):
        land_resp = self.client.post(
            "/claims",
            json={
                "claim_text": "I'm a Stanford student",
                "institution_name": "Stanford University",
                "device_signals": _device(
                    device_id="d-chal-1",
                    ip_address="10.1.0.3",
                    vpn_or_datacenter_ip=True,
                    mouse_movement_entropy=0.1,
                ),
            },
        )
        self.assertEqual(land_resp.status_code, 200)
        land_body = land_resp.json()
        self.assertEqual(land_body["verdict"], "CHALLENGE")
        self.assertEqual(sorted(land_body["required_proofs"]), ["document", "email", "identity"])
        session_id = land_body["session_id"]

        today = date.today()
        evidence_resp = self.client.post(
            f"/claims/{session_id}/evidence",
            json={
                "email_proof": {"email": "jane@stanford.edu"},
                "document_proof": {
                    "full_name": "Jane Doe",
                    "institution_name": "Stanford University",
                    "student_id_number": "SU-12345",
                    "issue_date": str(today - timedelta(days=100)),
                    "expiry_date": str(today + timedelta(days=365)),
                },
                "identity_proof": {
                    "method": "oauth",
                    "full_name": "Jane Doe",
                    "verified": True,
                },
            },
        )
        self.assertEqual(evidence_resp.status_code, 200)
        evidence_body = evidence_resp.json()
        self.assertEqual(evidence_body["verdict"], "PASS")
        self.assertIsNotNone(evidence_body["credential"])
        self.assertEqual(evidence_body["credential"]["assurance_level"], "verified_evidence")

    def test_challenge_then_deny_on_tampered_document(self):
        land_resp = self.client.post(
            "/claims",
            json={
                "claim_text": "I'm a Stanford student",
                "institution_name": "Stanford University",
                "device_signals": _device(
                    device_id="d-chal-2",
                    ip_address="10.1.0.4",
                    vpn_or_datacenter_ip=True,
                    mouse_movement_entropy=0.1,
                ),
            },
        )
        session_id = land_resp.json()["session_id"]

        today = date.today()
        evidence_resp = self.client.post(
            f"/claims/{session_id}/evidence",
            json={
                "email_proof": {"email": "jane@stanford.edu"},
                "document_proof": {
                    "full_name": "Jane Doe",
                    "institution_name": "Stanford University",
                    "student_id_number": "SU-12345",
                    "issue_date": str(today - timedelta(days=100)),
                    "expiry_date": str(today + timedelta(days=365)),
                    "tamper_suspected": True,
                },
                "identity_proof": {
                    "method": "oauth",
                    "full_name": "Jane Doe",
                    "verified": True,
                },
            },
        )
        self.assertEqual(evidence_resp.json()["verdict"], "DENY")
        self.assertIsNone(evidence_resp.json()["credential"])

    def test_cannot_submit_evidence_twice(self):
        land_resp = self.client.post(
            "/claims",
            json={
                "claim_text": "I'm a Stanford student",
                "institution_name": "Stanford University",
                "device_signals": _device(
                    device_id="d-chal-3",
                    ip_address="10.1.0.5",
                    vpn_or_datacenter_ip=True,
                    mouse_movement_entropy=0.1,
                ),
            },
        )
        session_id = land_resp.json()["session_id"]
        today = date.today()
        payload = {
            "email_proof": {"email": "jane@stanford.edu"},
            "document_proof": {
                "full_name": "Jane Doe",
                "institution_name": "Stanford University",
                "student_id_number": "SU-1",
                "issue_date": str(today - timedelta(days=10)),
                "expiry_date": str(today + timedelta(days=300)),
            },
            "identity_proof": {"method": "passkey", "full_name": "Jane Doe", "verified": True},
        }
        first = self.client.post(f"/claims/{session_id}/evidence", json=payload)
        self.assertEqual(first.status_code, 200)
        second = self.client.post(f"/claims/{session_id}/evidence", json=payload)
        self.assertEqual(second.status_code, 409)

    def test_unknown_session_404s(self):
        resp = self.client.get("/claims/does-not-exist")
        self.assertEqual(resp.status_code, 404)

    def test_malformed_claim_body_is_422(self):
        resp = self.client.post("/claims", json={"institution_name": "Stanford University"})
        self.assertEqual(resp.status_code, 422)


if __name__ == "__main__":
    unittest.main()
