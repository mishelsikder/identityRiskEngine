"""Session state machine.

    LANDED
       │  (Stage 1 fraud gate runs immediately)
       ├── PASSED_INITIAL ─────────────────────────────────┐
       ├── FAILED_INITIAL (terminal)                        │
       └── AWAITING_EVIDENCE                                 │
                │ (Stage 2 fraud + consistency gate)         │
                ├── PASSED_FINAL ─────────────────────┐      │
                ├── REVIEW_PENDING (terminal-ish)      │      │
                └── DENIED_FINAL (terminal)            │      │
                                                        ▼      ▼
                                                CREDENTIAL_ISSUED (terminal)

Kept as a tiny explicit graph (rather than letting routers set arbitrary
strings) so an invalid transition — e.g. submitting evidence twice, or
against a session that already failed — raises loudly instead of silently
corrupting state.
"""
from enum import Enum
from typing import Dict, Set


class SessionState(str, Enum):
    LANDED = "LANDED"
    PASSED_INITIAL = "PASSED_INITIAL"
    FAILED_INITIAL = "FAILED_INITIAL"
    AWAITING_EVIDENCE = "AWAITING_EVIDENCE"
    PASSED_FINAL = "PASSED_FINAL"
    REVIEW_PENDING = "REVIEW_PENDING"
    DENIED_FINAL = "DENIED_FINAL"
    CREDENTIAL_ISSUED = "CREDENTIAL_ISSUED"


TERMINAL_STATES: Set[SessionState] = {
    SessionState.FAILED_INITIAL,
    SessionState.REVIEW_PENDING,
    SessionState.DENIED_FINAL,
    SessionState.CREDENTIAL_ISSUED,
}

_ALLOWED_TRANSITIONS: Dict[SessionState, Set[SessionState]] = {
    SessionState.LANDED: {
        SessionState.PASSED_INITIAL,
        SessionState.FAILED_INITIAL,
        SessionState.AWAITING_EVIDENCE,
    },
    SessionState.PASSED_INITIAL: {SessionState.CREDENTIAL_ISSUED},
    SessionState.AWAITING_EVIDENCE: {
        SessionState.PASSED_FINAL,
        SessionState.REVIEW_PENDING,
        SessionState.DENIED_FINAL,
    },
    SessionState.PASSED_FINAL: {SessionState.CREDENTIAL_ISSUED},
}


class InvalidTransitionError(Exception):
    pass


def transition(current: SessionState, target: SessionState) -> SessionState:
    allowed = _ALLOWED_TRANSITIONS.get(current, set())
    if target not in allowed:
        raise InvalidTransitionError(
            f"Cannot transition session from {current} to {target}"
        )
    return target


def is_terminal(state: SessionState) -> bool:
    return state in TERMINAL_STATES
