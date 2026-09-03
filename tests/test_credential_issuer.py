import unittest

import jwt as pyjwt

from app.services.credential_issuer import credential_issuer
from app.models.verdict import AssuranceLevel


class TestCredentialIssuer(unittest.TestCase):
    def test_issue_and_verify_round_trip(self):
        credential = credential_issuer.issue(
            subject_id="subj_1",
            institution="Stanford University",
            assurance_level=AssuranceLevel.VERIFIED_EVIDENCE,
            risk_score=5,
            bot_score=5,
        )
        self.assertTrue(credential.token)
        claims = credential_issuer.verify(credential.token)
        self.assertEqual(claims["sub"], "subj_1")
        self.assertTrue(claims["vc"]["credentialSubject"]["student"])
        self.assertEqual(
            claims["vc"]["credentialSubject"]["institution"], "Stanford University"
        )

    def test_tampered_token_fails_verification(self):
        credential = credential_issuer.issue(
            subject_id="subj_2",
            institution="MIT",
            assurance_level=AssuranceLevel.SELF_ASSERTED,
            risk_score=5,
            bot_score=5,
        )
        tampered = credential.token[:-2] + ("aa" if credential.token[-2:] != "aa" else "bb")
        with self.assertRaises(pyjwt.PyJWTError):
            credential_issuer.verify(tampered)

    def test_jwks_exposes_public_key(self):
        jwks = credential_issuer.jwks()
        self.assertIn("keys", jwks)
        self.assertEqual(jwks["keys"][0]["kty"], "RSA")

    def test_get_returns_issued_credential(self):
        credential = credential_issuer.issue(
            subject_id="subj_3",
            institution="Harvard University",
            assurance_level=AssuranceLevel.SELF_ASSERTED,
            risk_score=1,
            bot_score=1,
        )
        fetched = credential_issuer.get(credential.credential_id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.credential_id, credential.credential_id)

    def test_get_unknown_credential_returns_none(self):
        self.assertIsNone(credential_issuer.get("vc_does_not_exist"))


if __name__ == "__main__":
    unittest.main()
