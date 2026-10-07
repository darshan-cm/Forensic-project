"""In-process session association for telemetry written without schema changes."""

from __future__ import annotations

from threading import RLock
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from reports.forensic_report import ForensicSession


_lock = RLock()
_active_session_id: str | None = None
_sessions: dict[str, ForensicSession] = {}


def register_session(session: ForensicSession) -> None:
    global _active_session_id
    with _lock:
        _sessions[session.session_id] = session
        _active_session_id = session.session_id


def active_session_id() -> str | None:
    with _lock:
        return _active_session_id


def record_event(session_id: str | None, event_row_id: int) -> None:
    if session_id is None:
        return
    with _lock:
        session = _sessions.get(session_id)
    if session is not None:
        session.record_event_row_id(event_row_id)


def record_assessment(session_id: str | None, assessment_id: int) -> None:
    if session_id is None:
        return
    with _lock:
        session = _sessions.get(session_id)
    if session is not None:
        session.record_assessment_row_id(assessment_id)


def finish_session(session_id: str) -> None:
    global _active_session_id
    with _lock:
        if _active_session_id == session_id:
            _active_session_id = None
