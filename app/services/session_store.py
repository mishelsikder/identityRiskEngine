"""In-memory session + abuse-history store.

Explicitly not durable — a process restart wipes it. That's the right
tradeoff for the "simulated" fidelity level chosen for this build; swap
this module for a Redis/Postgres-backed implementation before running this
for real, keeping the same interface (get/create/update session, plus the
velocity/reuse history helpers) so the routers and engine don't need to
change.
"""
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from app.models.claim import ClaimRequest
from app.models.evidence import EvidenceSubmission
from app.state_machine import SessionState


@dataclass
class Session:
    session_id: str
    subject_id: str
    claim: ClaimRequest
    state: SessionState = SessionState.LANDED
    created_at: float = field(default_factory=time.time)
    stage1_risk_score: Optional[int] = None
    stage1_bot_score: Optional[int] = None
    evidence: Optional[EvidenceSubmission] = None
    stage2_risk_score: Optional[int] = None
    stage2_bot_score: Optional[int] = None
    consistency_score: Optional[int] = None
    credential_id: Optional[str] = None


class SessionStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: Dict[str, Session] = {}
        # device_id / ip -> list of landing timestamps, for velocity scoring
        self._device_landings: Dict[str, List[float]] = {}
        self._ip_landings: Dict[str, List[float]] = {}
        # device_id -> set of institution names claimed, for reuse scoring
        self._device_institutions: Dict[str, Set[str]] = {}

    # -- session CRUD ------------------------------------------------
    def create_session(self, claim: ClaimRequest) -> Session:
        session_id = str(uuid.uuid4())
        subject_id = claim.subject_id or f"subj_{uuid.uuid4().hex[:12]}"
        session = Session(session_id=session_id, subject_id=subject_id, claim=claim)
        with self._lock:
            self._sessions[session_id] = session
        return session

    def get(self, session_id: str) -> Optional[Session]:
        return self._sessions.get(session_id)

    def save(self, session: Session) -> None:
        with self._lock:
            self._sessions[session.session_id] = session

    # -- abuse-history helpers (feed the fraud engine) ---------------
    def record_landing_and_get_velocity(
        self, device_id: str, ip_address: str, window_seconds: int
    ) -> int:
        """Records this landing and returns how many landings from the same
        device OR ip fell within the trailing window (including this one)."""
        now = time.time()
        with self._lock:
            device_hits = self._device_landings.setdefault(device_id, [])
            device_hits.append(now)
            ip_hits = self._ip_landings.setdefault(ip_address, [])
            ip_hits.append(now)

            cutoff = now - window_seconds
            device_hits[:] = [t for t in device_hits if t >= cutoff]
            ip_hits[:] = [t for t in ip_hits if t >= cutoff]
            return max(len(device_hits), len(ip_hits))

    def record_institution_and_get_reuse(self, device_id: str, institution_name: str) -> int:
        """Records this device's claimed institution and returns the count
        of *distinct* institutions this device has ever claimed."""
        with self._lock:
            seen = self._device_institutions.setdefault(device_id, set())
            seen.add(institution_name.strip().lower())
            return len(seen)


# Process-wide singleton — fine for a single-instance demo deployment.
session_store = SessionStore()
