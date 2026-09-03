import unittest

from app.engine import fraud_engine
from app.models.claim import ClaimRequest, DeviceSignals
from app.models.verdict import Verdict


def _claim(**device_overrides) -> ClaimRequest:
    defaults = dict(
        device_id="dev-1",
        ip_address="1.2.3.4",
        user_agent="Mozilla/5.0",
        known_device=False,
        vpn_or_datacenter_ip=False,
        mouse_movement_entropy=0.7,
        time_on_page_ms=4000,
    )
    defaults.update(device_overrides)
    signals = DeviceSignals(**defaults)
    return ClaimRequest(
        claim_text="I'm a Stanford student",
        institution_name="Stanford University",
        device_signals=signals,
    )


class TestStage1Gate(unittest.TestCase):
    def test_clean_signals_pass(self):
        claim = _claim(device_id="clean-device-1", ip_address="10.0.0.1", known_device=True)
        risk, bot, _, _ = fraud_engine.score_landing(claim)
        verdict = fraud_engine.gate_landing(risk, bot)
        self.assertEqual(verdict, Verdict.PASS)

    def test_bot_like_signals_fail(self):
        # No device fingerprint, no user agent, datacenter IP, near-zero
        # mouse entropy, near-instant submission: extreme on every axis at
        # once, enough to hard-fail even on a single request with no prior
        # abuse history.
        claim = _claim(
            device_id="",
            ip_address="10.0.0.2",
            vpn_or_datacenter_ip=True,
            mouse_movement_entropy=0.02,
            time_on_page_ms=50,
            user_agent="",
        )
        risk, bot, _, _ = fraud_engine.score_landing(claim)
        verdict = fraud_engine.gate_landing(risk, bot)
        self.assertEqual(verdict, Verdict.FAIL)

    def test_ambiguous_signals_challenge(self):
        # Datacenter IP plus low mouse entropy is suspicious but not extreme
        # enough on its own to hard-fail — this is exactly the ambiguous
        # middle the CHALLENGE step-up exists for.
        claim = _claim(
            device_id="ambiguous-device-1",
            ip_address="10.0.0.3",
            vpn_or_datacenter_ip=True,
            mouse_movement_entropy=0.1,
        )
        risk, bot, _, _ = fraud_engine.score_landing(claim)
        verdict = fraud_engine.gate_landing(risk, bot)
        self.assertEqual(verdict, Verdict.CHALLENGE)


class TestStage2Gate(unittest.TestCase):
    def test_full_consistency_passes(self):
        risk, bot, _, _ = fraud_engine.score_evidence(
            claim=_claim(),
            stage1_risk_score=10,
            stage1_bot_score=10,
            consistency_score=100,
            hard_deny=False,
        )
        verdict = fraud_engine.gate_evidence(risk, bot, hard_deny=False)
        self.assertEqual(verdict, Verdict.PASS)

    def test_hard_deny_overrides_good_scores(self):
        risk, bot, _, _ = fraud_engine.score_evidence(
            claim=_claim(),
            stage1_risk_score=5,
            stage1_bot_score=5,
            consistency_score=90,
            hard_deny=True,
        )
        verdict = fraud_engine.gate_evidence(risk, bot, hard_deny=True)
        self.assertEqual(verdict, Verdict.DENY)

    def test_moderate_inconsistency_review(self):
        risk, bot, _, _ = fraud_engine.score_evidence(
            claim=_claim(),
            stage1_risk_score=30,
            stage1_bot_score=25,
            consistency_score=40,
            hard_deny=False,
        )
        verdict = fraud_engine.gate_evidence(risk, bot, hard_deny=False)
        self.assertEqual(verdict, Verdict.REVIEW)


if __name__ == "__main__":
    unittest.main()
