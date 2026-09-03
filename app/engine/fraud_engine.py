"""The AI Fraud Engine.

Runs twice per claim lifecycle:

  * ``score_landing`` — the instant the user lands with a claim, using only
    behavioral/device signals (velocity, reuse, device, anomalies). Produces
    the PASS / FAIL / CHALLENGE gate.
  * ``score_evidence`` — after a CHALLENGE has been answered with proofs,
    folding in the evidence-consistency check. Produces the final
    PASS / REVIEW / DENY decision.

"Rule-based, deterministic weighted scoring" is a stand-in for a trained
model here (per the chosen simulated fidelity level). Every sub-scorer
below is a single, small, independently testable function — that's the
intended seam for dropping in a real ML/behavioral-biometrics model later
without touching the gating logic in the routers.
"""
from typing import List, Tuple

from app import config
from app.engine.scoring import clamp
from app.models.claim import ClaimRequest, DeviceSignals
from app.models.decision import RiskScoreBreakdown
from app.models.evidence import EvidenceSubmission
from app.models.verdict import Verdict
from app.services.session_store import session_store


# ---------------------------------------------------------------------------
# Stage 1 sub-scorers — behavioral/device signals only
# ---------------------------------------------------------------------------
def _velocity_score(device_id: str, ip_address: str) -> int:
    count = session_store.record_landing_and_get_velocity(
        device_id, ip_address, config.VELOCITY_WINDOW_SECONDS
    )
    if count <= 1:
        return 0
    if count < config.VELOCITY_HIGH_COUNT:
        return 35
    # Scale up past the "high" threshold, capped at 100
    return clamp(35 + (count - config.VELOCITY_HIGH_COUNT + 1) * 20)


def _reuse_score(device_id: str, institution_name: str) -> int:
    distinct = session_store.record_institution_and_get_reuse(device_id, institution_name)
    if distinct <= 1:
        return 0
    if distinct < config.REUSE_HIGH_DISTINCT_INSTITUTIONS + 1:
        return 40
    return clamp(40 + (distinct - config.REUSE_HIGH_DISTINCT_INSTITUTIONS) * 25)


def _device_score(signals: DeviceSignals) -> int:
    score = 0
    if not signals.device_id:
        score += 50
    if not signals.user_agent:
        score += 30
    if signals.known_device:
        score -= 25
    return clamp(score)


def _anomaly_score(signals: DeviceSignals) -> int:
    score = 0
    if signals.vpn_or_datacenter_ip:
        score += 35
    if signals.mouse_movement_entropy < 0.15:
        score += 30
    if signals.time_on_page_ms < 400:
        score += 35
    return clamp(score)


def score_landing(claim: ClaimRequest) -> Tuple[int, int, RiskScoreBreakdown, List[str]]:
    """Returns (risk_score, bot_score, breakdown, reasons)."""
    signals = claim.device_signals
    velocity = _velocity_score(signals.device_id, signals.ip_address)
    reuse = _reuse_score(signals.device_id, claim.institution_name)
    device = _device_score(signals)
    anomaly = _anomaly_score(signals)

    # risk_score emphasizes fraud/abuse-farming signals (velocity + reuse);
    # bot_score emphasizes automation signals (device + anomaly) so a single,
    # sufficiently extreme automated-looking request can be caught even
    # with no prior history to build velocity/reuse from.
    risk_score = clamp(0.30 * velocity + 0.30 * reuse + 0.20 * device + 0.20 * anomaly)
    bot_score = clamp(0.05 * velocity + 0.05 * reuse + 0.35 * device + 0.55 * anomaly)

    reasons: List[str] = []
    if velocity:
        reasons.append(f"velocity signal elevated ({velocity}/100)")
    if reuse:
        reasons.append(f"device has claimed multiple distinct institutions ({reuse}/100)")
    if device:
        reasons.append(f"device fingerprint looks weak/unfamiliar ({device}/100)")
    if anomaly:
        reasons.append(f"behavioral anomalies detected ({anomaly}/100)")
    if not reasons:
        reasons.append("no elevated risk signals at landing")

    breakdown = RiskScoreBreakdown(
        velocity_score=velocity, reuse_score=reuse, device_score=device, anomaly_score=anomaly
    )
    return risk_score, bot_score, breakdown, reasons


def gate_landing(risk_score: int, bot_score: int) -> Verdict:
    if risk_score >= config.STAGE1_FAIL_MIN_RISK or bot_score >= config.STAGE1_FAIL_MIN_BOT:
        return Verdict.FAIL
    if risk_score <= config.STAGE1_PASS_MAX_RISK and bot_score <= config.STAGE1_PASS_MAX_BOT:
        return Verdict.PASS
    return Verdict.CHALLENGE


# ---------------------------------------------------------------------------
# Stage 2 — fold in evidence consistency on top of the Stage 1 signals
# ---------------------------------------------------------------------------
def score_evidence(
    claim: ClaimRequest,
    stage1_risk_score: int,
    stage1_bot_score: int,
    consistency_score: int,
    hard_deny: bool,
) -> Tuple[int, int, RiskScoreBreakdown, List[str]]:
    """Blends the original behavioral scores with the evidence-consistency
    penalty. consistency_score is 0-100 where 100 = fully consistent."""
    consistency_penalty = clamp(100 - consistency_score)

    final_risk = clamp(0.55 * stage1_risk_score + 0.45 * consistency_penalty)
    final_bot = clamp(0.7 * stage1_bot_score + 0.3 * consistency_penalty)

    reasons: List[str] = []
    if consistency_penalty:
        reasons.append(f"evidence consistency penalty applied ({consistency_penalty}/100)")
    if hard_deny:
        reasons.append("hard-deny condition triggered by evidence check (see consistency reasons)")
        final_risk = max(final_risk, config.STAGE2_DENY_MIN_RISK)
    if not reasons:
        reasons.append("evidence fully consistent, no additional penalty")

    breakdown = RiskScoreBreakdown(
        velocity_score=0,
        reuse_score=0,
        device_score=0,
        anomaly_score=0,
        consistency_penalty=consistency_penalty,
    )
    return final_risk, final_bot, breakdown, reasons


def gate_evidence(risk_score: int, bot_score: int, hard_deny: bool) -> Verdict:
    if hard_deny or risk_score >= config.STAGE2_DENY_MIN_RISK or bot_score >= config.STAGE2_DENY_MIN_RISK:
        return Verdict.DENY
    if risk_score >= config.STAGE2_REVIEW_MIN_RISK or bot_score >= config.STAGE2_REVIEW_MIN_RISK:
        return Verdict.REVIEW
    return Verdict.PASS
