from starlette.requests import Request
from starlette.responses import JSONResponse

from app import config
from app.engine import fraud_engine
from app.http import ApiError, parse_body
from app.models.claim import ClaimRequest
from app.models.decision import ClaimLandingResponse
from app.models.verdict import AssuranceLevel, Verdict
from app.services.credential_issuer import credential_issuer
from app.services.session_store import session_store
from app.state_machine import SessionState, transition


async def land_claim(request: Request) -> JSONResponse:
    """POST /claims — the moment a user lands with a claim, the AI Fraud
    Engine runs first, before any evidence is collected, using only
    behavioral/device signals."""
    claim = await parse_body(request, ClaimRequest)
    session = session_store.create_session(claim)

    risk_score, bot_score, breakdown, reasons = fraud_engine.score_landing(claim)
    verdict = fraud_engine.gate_landing(risk_score, bot_score)

    session.stage1_risk_score = risk_score
    session.stage1_bot_score = bot_score

    credential = None
    required_proofs = []

    if verdict == Verdict.PASS:
        session.state = transition(session.state, SessionState.PASSED_INITIAL)
        credential = credential_issuer.issue(
            subject_id=session.subject_id,
            institution=claim.institution_name,
            assurance_level=AssuranceLevel.SELF_ASSERTED,
            risk_score=risk_score,
            bot_score=bot_score,
        )
        session.credential_id = credential.credential_id
        session.state = transition(session.state, SessionState.CREDENTIAL_ISSUED)
    elif verdict == Verdict.FAIL:
        session.state = transition(session.state, SessionState.FAILED_INITIAL)
    else:  # CHALLENGE
        session.state = transition(session.state, SessionState.AWAITING_EVIDENCE)
        required_proofs = config.REQUIRED_PROOFS_ON_CHALLENGE

    session_store.save(session)

    response = ClaimLandingResponse(
        session_id=session.session_id,
        verdict=verdict,
        risk_score=risk_score,
        bot_score=bot_score,
        breakdown=breakdown,
        reasons=reasons,
        required_proofs=required_proofs,
        credential=credential,
    )
    return JSONResponse(response.model_dump(mode="json"))


async def get_claim_session(request: Request) -> JSONResponse:
    """GET /claims/{session_id} — inspect a session's current state (mainly
    useful for debugging/demoing the state machine)."""
    session_id = request.path_params["session_id"]
    session = session_store.get(session_id)
    if session is None:
        raise ApiError(404, "session not found")
    return JSONResponse(
        {
            "session_id": session.session_id,
            "state": session.state.value,
            "subject_id": session.subject_id,
            "stage1_risk_score": session.stage1_risk_score,
            "stage1_bot_score": session.stage1_bot_score,
            "stage2_risk_score": session.stage2_risk_score,
            "stage2_bot_score": session.stage2_bot_score,
            "consistency_score": session.consistency_score,
            "credential_id": session.credential_id,
        }
    )
