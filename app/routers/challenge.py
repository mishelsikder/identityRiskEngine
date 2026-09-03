from starlette.requests import Request
from starlette.responses import JSONResponse

from app.engine import fraud_engine
from app.engine.evidence_checker import check_evidence
from app.http import ApiError, parse_body
from app.models.decision import EvidenceDecisionResponse
from app.models.evidence import EvidenceSubmission
from app.models.verdict import AssuranceLevel, Verdict
from app.services.credential_issuer import credential_issuer
from app.services.session_store import session_store
from app.state_machine import SessionState, transition


async def submit_evidence(request: Request) -> JSONResponse:
    """POST /claims/{session_id}/evidence — the CHALLENGE follow-up: evidence
    proofs are checked for internal consistency, then re-scored by the fraud
    engine alongside the original Stage 1 behavioral signals to produce a
    final PASS / REVIEW / DENY."""
    session_id = request.path_params["session_id"]
    session = session_store.get(session_id)
    if session is None:
        raise ApiError(404, "session not found")
    if session.state != SessionState.AWAITING_EVIDENCE:
        raise ApiError(409, f"session is not awaiting evidence (state={session.state.value})")

    evidence = await parse_body(request, EvidenceSubmission)

    check_result = check_evidence(session.claim, evidence)
    session.evidence = evidence
    session.consistency_score = check_result.consistency_score

    risk_score, bot_score, breakdown, reasons = fraud_engine.score_evidence(
        claim=session.claim,
        stage1_risk_score=session.stage1_risk_score or 0,
        stage1_bot_score=session.stage1_bot_score or 0,
        consistency_score=check_result.consistency_score,
        hard_deny=check_result.hard_deny,
    )
    reasons = check_result.reasons + reasons
    verdict = fraud_engine.gate_evidence(risk_score, bot_score, check_result.hard_deny)

    session.stage2_risk_score = risk_score
    session.stage2_bot_score = bot_score

    credential = None
    if verdict == Verdict.PASS:
        session.state = transition(session.state, SessionState.PASSED_FINAL)
        credential = credential_issuer.issue(
            subject_id=session.subject_id,
            institution=session.claim.institution_name,
            assurance_level=AssuranceLevel.VERIFIED_EVIDENCE,
            risk_score=risk_score,
            bot_score=bot_score,
        )
        session.credential_id = credential.credential_id
        session.state = transition(session.state, SessionState.CREDENTIAL_ISSUED)
    elif verdict == Verdict.REVIEW:
        session.state = transition(session.state, SessionState.REVIEW_PENDING)
    else:  # DENY
        session.state = transition(session.state, SessionState.DENIED_FINAL)

    session_store.save(session)

    response = EvidenceDecisionResponse(
        session_id=session.session_id,
        verdict=verdict,
        risk_score=risk_score,
        bot_score=bot_score,
        consistency_score=check_result.consistency_score,
        breakdown=breakdown,
        reasons=reasons,
        credential=credential,
    )
    return JSONResponse(response.model_dump(mode="json"))
