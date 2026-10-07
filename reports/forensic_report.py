"""Session-scoped, offline PDF reports built from existing telemetry."""

from __future__ import annotations

import os
import re
import sqlite3
import json
import uuid
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Table,
    TableStyle,
)

from detection.rule_registry import get_rule
from reports.session_context import finish_session, register_session

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FORENSIC_DB_PATH = PROJECT_ROOT / "database" / "forensic.db"
RISK_DB_PATH = PROJECT_ROOT / "database" / "riskalert.db"
REPORT_DIRECTORY = PROJECT_ROOT / "reports"
MAX_TEXT_LENGTH = 500
MAX_TIMELINE_ITEMS = 30


def _database_connection(path: Path) -> sqlite3.Connection:
    resolved = Path(path).resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"Telemetry database not found: {resolved}")
    return sqlite3.connect(f"{resolved.as_uri()}?mode=ro", uri=True, timeout=5)


@contextmanager
def _read_connection(path: Path):
    connection = _database_connection(path)
    try:
        yield connection
    finally:
        connection.close()


def _authenticated_user_info(user: Any) -> tuple[str | None, str | None]:
    if user is None:
        return None, None
    if isinstance(user, dict):
        user_id = user.get("id")
        email = user.get("email")
    else:
        user_id = getattr(user, "id", None)
        email = getattr(user, "email", None)
    safe_id = str(user_id).strip()[:200] if user_id is not None else ""
    safe_email = str(email).strip()[:254] if email is not None else ""
    if "@" not in safe_email or any(char.isspace() for char in safe_email):
        safe_email = ""
    return safe_id or None, safe_email or None


def _timestamp(value: datetime) -> str:
    return value.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _bounded_text(value: Any, limit: int = MAX_TEXT_LENGTH) -> str:
    if value is None:
        return ""
    text = re.sub(r"\s+", " ", str(value)).strip()
    text = re.sub(
        r"(?i)\b(password|passwd|secret|token|api[_ -]?key|authorization)"
        r"\s*[:=]\s*([^\s,;]+)",
        r"\1=[REDACTED]",
        text,
    )
    text = re.sub(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", text)
    return text[:limit] + ("..." if len(text) > limit else "")


def _pdf_text(value: Any) -> str:
    text = _bounded_text(value, 1200)
    return escape(text.encode("latin-1", "replace").decode("latin-1"))


@dataclass
class ForensicSession:
    """Session boundaries and row-ID associations without telemetry migrations."""

    user_id: str | None = None
    user_email: str | None = None
    forensic_db_path: Path = FORENSIC_DB_PATH
    risk_db_path: Path = RISK_DB_PATH
    report_directory: Path = REPORT_DIRECTORY
    started_at: datetime = field(default_factory=lambda: datetime.now().astimezone())
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    initial_event_id: int = field(init=False)
    initial_assessment_id: int = field(init=False)
    metadata_path: Path = field(init=False)
    associations_path: Path = field(init=False)
    _association_lock: RLock = field(init=False, repr=False)
    _closed_at: datetime | None = field(default=None, init=False, repr=False)
    _last_report_path: Path | None = field(default=None, init=False, repr=False)
    _last_report_at: datetime | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.forensic_db_path = Path(self.forensic_db_path)
        self.risk_db_path = Path(self.risk_db_path)
        self.report_directory = Path(self.report_directory)
        self._association_lock = RLock()
        self.initial_event_id = self._latest_id(
            self.forensic_db_path, "events"
        )
        self.initial_assessment_id = self._latest_id(
            self.risk_db_path, "risk_assessments"
        )
        session_directory = self.report_directory / ".sessions"
        session_directory.mkdir(parents=True, exist_ok=True)
        self.metadata_path = session_directory / f"{self.session_id}.json"
        self.associations_path = session_directory / f"{self.session_id}.jsonl"
        self._write_session_metadata()
        register_session(self)

    @classmethod
    def start(
        cls,
        user: Any,
        *,
        forensic_db_path: Path = FORENSIC_DB_PATH,
        risk_db_path: Path = RISK_DB_PATH,
        report_directory: Path = REPORT_DIRECTORY,
    ) -> "ForensicSession":
        user_id, user_email = _authenticated_user_info(user)
        return cls(
            user_id=user_id,
            user_email=user_email,
            forensic_db_path=forensic_db_path,
            risk_db_path=risk_db_path,
            report_directory=report_directory,
        )

    @staticmethod
    def _latest_id(path: Path, table: str) -> int:
        if table not in {"events", "risk_assessments"}:
            raise ValueError(f"Unsupported telemetry table: {table}")
        with _read_connection(path) as connection:
            row = connection.execute(
                f"SELECT COALESCE(MAX(id), 0) FROM {table}"
            ).fetchone()
        return int(row[0])

    def record_event_row_id(self, event_row_id: int) -> None:
        self._append_association("event", event_row_id)

    def record_assessment_row_id(self, assessment_row_id: int) -> None:
        self._append_association("assessment", assessment_row_id)

    def _append_association(self, record_type: str, row_id: int) -> None:
        if record_type not in {"event", "assessment"}:
            raise ValueError(f"Unsupported session association type: {record_type}")
        if row_id <= 0:
            raise ValueError("Associated database row IDs must be positive.")
        with self._association_lock:
            if self._closed_at is not None:
                return
            with self.associations_path.open("a", encoding="utf-8") as ledger:
                ledger.write(
                    json.dumps(
                        {"type": record_type, "row_id": row_id},
                        separators=(",", ":"),
                    )
                    + "\n"
                )
                ledger.flush()

    def _associated_row_ids(self, record_type: str) -> list[int]:
        if not self.associations_path.exists():
            return []
        row_ids: list[int] = []
        with self._association_lock:
            with self.associations_path.open("r", encoding="utf-8") as ledger:
                for line_number, line in enumerate(ledger, start=1):
                    try:
                        item = json.loads(line)
                        if item.get("type") == record_type:
                            row_ids.append(int(item["row_id"]))
                    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
                        raise ValueError(
                            f"Invalid session association ledger "
                            f"{self.associations_path} at line {line_number}."
                        ) from error
        return row_ids

    def _write_session_metadata(
        self,
        *,
        ended_at: datetime | None = None,
        last_report: Path | None = None,
    ) -> None:
        metadata = {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "user_email": self.user_email,
            "started_at": _timestamp(self.started_at),
            "ended_at": _timestamp(ended_at) if ended_at else None,
            "initial_event_row_id": self.initial_event_id,
            "initial_assessment_row_id": self.initial_assessment_id,
            "historical_rows_associated": False,
            "association_ledger": self.associations_path.name,
            "last_report": last_report.name if last_report else None,
        }
        temporary_path = self.metadata_path.with_suffix(".json.tmp")
        temporary_path.write_text(
            json.dumps(metadata, indent=2),
            encoding="utf-8",
        )
        os.replace(temporary_path, self.metadata_path)

    def finish(self, ended_at: datetime | None = None) -> None:
        end_time = ended_at or self._last_report_at or datetime.now().astimezone()
        if end_time.tzinfo is None:
            end_time = end_time.astimezone()
        if end_time < self.started_at:
            raise ValueError("Session end cannot precede the session start.")
        with self._association_lock:
            self._write_session_metadata(
                ended_at=end_time,
                last_report=self._last_report_path,
            )
            self._closed_at = end_time
        finish_session(self.session_id)

    def generate_report(self, report_time: datetime | None = None) -> Path:
        from event_engine.engine import wait_until_idle

        if not wait_until_idle(timeout=5):
            raise TimeoutError(
                "Forensic event processing is still pending; retry report generation."
            )
        end_time = report_time or datetime.now().astimezone()
        if end_time.tzinfo is None:
            end_time = end_time.astimezone()
        if end_time < self.started_at:
            raise ValueError("Report time cannot precede the session start.")

        event_row_ids = self._associated_row_ids("event")
        assessment_row_ids = self._associated_row_ids("assessment")
        events = self._session_events(event_row_ids)
        assessments = self._session_assessments(assessment_row_ids)
        evidence = self._session_evidence(assessments)
        report_id = uuid.uuid4().hex
        report_data = self._build_report_data(
            end_time, events, assessments, evidence, report_id
        )

        self.report_directory.mkdir(parents=True, exist_ok=True)
        generated_stamp = end_time.strftime("%Y%m%d_%H%M%S_%f")
        filename = (
            f"ForensicGuard_Report_{self.session_id}_{generated_stamp}_"
            f"{report_id}.pdf"
        )
        destination = self.report_directory / filename
        temporary_path = destination.with_suffix(".pdf.tmp")
        try:
            self._write_pdf(temporary_path, report_data)
            self._verify_pdf(temporary_path)
            os.replace(temporary_path, destination)
            self._verify_pdf(destination)
            self._last_report_path = destination
            self._last_report_at = end_time
            self._write_session_metadata(
                ended_at=self._closed_at,
                last_report=destination,
            )
        except Exception:
            if temporary_path.exists():
                temporary_path.unlink()
            raise
        return destination

    def _session_events(
        self, event_row_ids: list[int] | None = None
    ) -> list[dict[str, Any]]:
        event_row_ids = (
            self._associated_row_ids("event")
            if event_row_ids is None
            else event_row_ids
        )
        if not event_row_ids:
            return []
        rows: list[sqlite3.Row] = []
        with _read_connection(self.forensic_db_path) as connection:
            connection.row_factory = sqlite3.Row
            for start in range(0, len(event_row_ids), 500):
                batch = event_row_ids[start:start + 500]
                placeholders = ",".join("?" for _ in batch)
                rows.extend(
                    connection.execute(
                        f"""
                        SELECT id, timestamp, source, event_id, action, application, details
                        FROM events
                        WHERE id IN ({placeholders})
                        ORDER BY id
                        """,
                        batch,
                    ).fetchall()
                )
        return [dict(row) for row in rows]

    def _session_assessments(
        self, assessment_row_ids: list[int] | None = None
    ) -> list[dict[str, Any]]:
        assessment_row_ids = (
            self._associated_row_ids("assessment")
            if assessment_row_ids is None
            else assessment_row_ids
        )
        if not assessment_row_ids:
            return []
        rows: list[sqlite3.Row] = []
        with _read_connection(self.risk_db_path) as connection:
            connection.row_factory = sqlite3.Row
            for start in range(0, len(assessment_row_ids), 500):
                batch = assessment_row_ids[start:start + 500]
                placeholders = ",".join("?" for _ in batch)
                rows.extend(
                    connection.execute(
                        f"""
                        SELECT id, timestamp, risk_level, risk_score, activity_type,
                               trigger_event_id, trigger_event_source, trigger_application,
                               trigger_details, rule_id, rule_name, evidence_summary,
                               alert_message
                        FROM risk_assessments
                        WHERE id IN ({placeholders})
                          AND (trigger_event_id IS NOT NULL OR rule_id IS NOT NULL)
                        ORDER BY id
                        """,
                        batch,
                    ).fetchall()
                )
        return [dict(row) for row in rows]

    def _session_evidence(
        self, assessments: list[dict[str, Any]]
    ) -> dict[int, list[dict[str, Any]]]:
        assessment_ids = [int(row["id"]) for row in assessments]
        if not assessment_ids:
            return {}
        placeholders = ",".join("?" for _ in assessment_ids)
        with _read_connection(self.risk_db_path) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                f"""
                SELECT id, risk_id, evidence_text, event_id, event_source, details,
                       file_path, source_path, destination_path, usb_device
                FROM risk_evidence
                WHERE risk_id IN ({placeholders})
                ORDER BY id
                """,
                assessment_ids,
            ).fetchall()
        evidence: dict[int, list[dict[str, Any]]] = {}
        for row in rows:
            evidence.setdefault(int(row["risk_id"]), []).append(dict(row))
        return evidence

    def _build_report_data(
        self,
        end_time: datetime,
        events: list[dict[str, Any]],
        assessments: list[dict[str, Any]],
        evidence: dict[int, list[dict[str, Any]]],
        report_id: str | None = None,
    ) -> dict[str, Any]:
        categories = Counter(_event_category(event) for event in events)
        scores = [
            (
                int(row["risk_score"]),
                _risk_level(row["risk_level"]),
                row,
            )
            for row in assessments
            if row.get("risk_score") is not None
        ]
        highest_score, risk_level, highest_assessment = max(
            scores,
            key=lambda item: (item[0], _severity_rank(item[1])),
            default=(0, "LOW", None),
        )
        distinct_rules = {
            _official_rule_name(row)
            for row in assessments
            if row.get("rule_id") is not None
        }
        unassociated_events = [
            event
            for event in events
            if not any(
                _event_matches_assessment(event, assessment)
                for assessment in assessments
            )
        ]
        normal_activity_counts = _activity_counts(unassociated_events)
        activity_counts = _activity_counts(events)
        risk_level_counts = Counter(
            _risk_level(row.get("risk_level")) for row in assessments
        )
        return {
            "report_id": report_id or uuid.uuid4().hex,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "user_email": self.user_email,
            "started_at": self.started_at,
            "ended_at": end_time,
            "events": events,
            "assessments": assessments,
            "evidence": evidence,
            "categories": categories,
            "activity_counts": activity_counts,
            "risk_score": highest_score,
            "risk_level": risk_level,
            "risk_level_counts": risk_level_counts,
            "highest_assessment": highest_assessment,
            "distinct_rules": distinct_rules,
            "key_findings": _key_findings(assessments, activity_counts),
            "recommendations": _recommendations(risk_level, assessments),
            "timeline": _timeline(
                events,
                assessments,
                evidence,
                self.started_at,
                end_time,
            ),
            "normal_summary": _normal_activity_summary(
                len(unassociated_events),
                normal_activity_counts,
            ),
            "analysis": _analysis(assessments, events, risk_level),
            "conclusion": _final_assessment(risk_level, assessments),
        }

    @staticmethod
    def _verify_pdf(path: Path) -> None:
        content = path.read_bytes()
        startxref_match = re.search(rb"startxref\s+(\d+)", content[-1024:])
        if len(content) < 100 or not content.startswith(b"%PDF-"):
            raise ValueError(f"Generated report is not a readable PDF: {path}")
        if b"%%EOF" not in content[-2048:] or b"/Type /Page" not in content:
            raise ValueError(f"Generated report is incomplete: {path}")
        if startxref_match is None:
            raise ValueError(f"Generated report has no PDF cross-reference: {path}")
        xref_offset = int(startxref_match.group(1))
        if content[xref_offset:xref_offset + 4] != b"xref":
            raise ValueError(f"Generated report has an invalid cross-reference: {path}")
        trailer_start = content.find(b"trailer", xref_offset)
        trailer_end = content.find(b"startxref", trailer_start)
        root_match = re.search(
            rb"/Root\s+(\d+)\s+(\d+)\s+R",
            content[trailer_start:trailer_end],
        )
        if root_match is None:
            raise ValueError(f"Generated report has no PDF document root: {path}")
        root_object = (
            rb"(?m)^\s*"
            + root_match.group(1)
            + rb"\s+"
            + root_match.group(2)
            + rb"\s+obj\b"
        )
        if re.search(root_object, content[:xref_offset]) is None:
            raise ValueError(f"Generated report document root is missing: {path}")

    @staticmethod
    def _write_pdf(path: Path, data: dict[str, Any]) -> None:
        styles = getSampleStyleSheet()
        styles.add(
            ParagraphStyle(
                name="FGTitle",
                parent=styles["Title"],
                fontName="Helvetica-Bold",
                fontSize=13,
                leading=15,
                alignment=TA_LEFT,
                spaceAfter=2,
            )
        )
        styles.add(
            ParagraphStyle(
                name="FGBody",
                parent=styles["BodyText"],
                fontName="Helvetica",
                fontSize=7.2,
                leading=9,
                spaceAfter=2,
            )
        )
        styles.add(
            ParagraphStyle(
                name="FGSection",
                parent=styles["Heading2"],
                fontName="Helvetica-Bold",
                fontSize=9,
                leading=11,
                spaceBefore=5,
                spaceAfter=3,
            )
        )
        styles.add(
            ParagraphStyle(
                name="FGSmall",
                parent=styles["BodyText"],
                fontName="Helvetica",
                fontSize=6.2,
                leading=7.4,
            )
        )

        document = SimpleDocTemplate(
            str(path),
            pagesize=A4,
            rightMargin=13 * mm,
            leftMargin=13 * mm,
            topMargin=10 * mm,
            bottomMargin=10 * mm,
            pageCompression=1,
            title="ForensicGuard Forensic Report",
            author="ForensicGuard",
        )
        story: list[Any] = [
            Paragraph("ForensicGuard", styles["FGTitle"]),
            Paragraph("Digital Forensics &amp; Security Monitoring", styles["FGBody"]),
            Paragraph("Forensic Monitoring Session Report", styles["FGSection"]),
            Paragraph(
                f"Report ID: {_pdf_text(data['report_id'])}",
                styles["FGBody"],
            ),
            Paragraph(
                f"Report generated: {_pdf_text(_timestamp(data['ended_at']))}",
                styles["FGBody"],
            ),
            Paragraph("Session Information", styles["FGSection"]),
            _table(
                [
                    ["Session ID", data["session_id"]],
                    ["Authenticated user ID", data["user_id"] or "Not available"],
                    ["Authenticated email", data["user_email"] or "Not available"],
                    ["Login time", _timestamp(data["started_at"])],
                    ["Report/logout time", _timestamp(data["ended_at"])],
                    ["Duration", _duration(data["started_at"], data["ended_at"])],
                ],
                widths=[36 * mm, 145 * mm],
                font_size=7,
            ),
            Paragraph("Activity Summary", styles["FGSection"]),
            _table(
                [
                    ["Total events", str(len(data["events"]))],
                    ["File Created", str(data["activity_counts"]["file_created"])],
                    ["File Modified", str(data["activity_counts"]["file_modified"])],
                    ["File Deleted", str(data["activity_counts"]["file_deleted"])],
                    ["File Renamed", str(data["activity_counts"]["file_renamed"])],
                    ["File Moved", str(data["activity_counts"]["file_moved"])],
                    ["USB/removable activity", str(data["activity_counts"]["usb"])],
                    ["File-transfer activity", str(data["activity_counts"]["file_transfer"])],
                    ["Security events", str(data["activity_counts"]["security"])],
                    ["Other monitored events", str(data["activity_counts"]["other"])],
                ],
                widths=[75 * mm, 35 * mm],
                font_size=7,
            ),
            Paragraph(
                "Counts describe observed telemetry; an event without a matched "
                "risk rule is not thereby certified as safe.",
                styles["FGSmall"],
            ),
            Paragraph("Risk Summary", styles["FGSection"]),
            _table(
                [
                    ["Session risk score", f"{data['risk_score']} / 100"],
                    ["Risk level", data["risk_level"]],
                    ["Rule-tagged/triggered assessments", str(len(data["assessments"]))],
                    ["LOW assessments", str(data["risk_level_counts"]["LOW"])],
                    ["MEDIUM assessments", str(data["risk_level_counts"]["MEDIUM"])],
                    ["HIGH assessments", str(data["risk_level_counts"]["HIGH"])],
                    ["CRITICAL assessments", str(data["risk_level_counts"]["CRITICAL"])],
                    ["Distinct rules triggered", str(len(data["distinct_rules"]))],
                    ["Highest assessment score", f"{data['risk_score']} / 100"],
                    [
                        "Highest-risk activity",
                        _highest_activity_label(data["highest_assessment"]),
                    ],
                ],
                widths=[75 * mm, 35 * mm],
                font_size=7,
            ),
            Paragraph("Detected Suspicious Activity", styles["FGSection"]),
        ]

        if data["assessments"]:
            suspicious_rows = [[
                "Time", "Rule", "Level/Score", "Description and evidence"
            ]]
            for assessment in data["assessments"]:
                rule = (
                    f"Rule {assessment['rule_id']}: {assessment['rule_name']}"
                    if assessment.get("rule_id") is not None
                    else str(assessment.get("activity_type") or "Triggered assessment")
                )
                if assessment.get("rule_id") is not None:
                    rule = _official_rule_name(assessment)
                details = assessment.get("trigger_details") or assessment.get("evidence_summary")
                detail_evidence = data["evidence"].get(int(assessment["id"]), [])
                if detail_evidence:
                    details = " | ".join(
                        filter(
                            None,
                            [
                                str(details or ""),
                                *[
                                    str(item.get("evidence_text") or item.get("details") or "")
                                    for item in detail_evidence[:3]
                                ],
                            ],
                        )
                    )
                suspicious_rows.append(
                    [
                        _timestamp_from_db(assessment.get("timestamp")),
                        rule,
                        f"{_risk_level(assessment['risk_level'])} / "
                        f"{assessment['risk_score']}",
                        _bounded_text(details or "No evidence text stored.", 240),
                    ]
                )
            story.append(
                _table(
                    suspicious_rows,
                    widths=[24 * mm, 40 * mm, 25 * mm, 95 * mm],
                    font_size=6,
                )
            )
        else:
            story.append(
                Paragraph(
                    "No supported suspicious rule was triggered in the "
                    "session-scoped assessments.",
                    styles["FGBody"],
                )
            )

        evidence_rows = [[
            "Evidence ID",
            "Timestamp",
            "Rule / event / source",
            "Observed evidence",
        ]]
        for assessment in data["assessments"]:
            rule_name = _official_rule_name(assessment)
            rows = data["evidence"].get(int(assessment["id"]), [])
            for item in rows[:5]:
                evidence_details = " | ".join(
                    value
                    for value in (
                        _bounded_text(item.get("evidence_text"), 140),
                        _bounded_text(item.get("details"), 120),
                        _bounded_text(item.get("file_path"), 120),
                        _bounded_text(item.get("source_path"), 120),
                        _bounded_text(item.get("destination_path"), 120),
                        _bounded_text(item.get("usb_device"), 80),
                    )
                    if value
                )
                evidence_rows.append(
                    [
                        str(item["id"]),
                        _timestamp_from_db(assessment.get("timestamp")),
                        (
                            f"{rule_name} / "
                            f"{item.get('event_id') or 'event unknown'} "
                            f"({item.get('event_source') or 'source unknown'})"
                        ),
                        evidence_details or "No additional evidence detail stored.",
                    ]
                )
        story.append(Paragraph("Forensic Evidence Summary", styles["FGSection"]))
        if len(evidence_rows) == 1:
            story.append(
                Paragraph(
                    "No separate evidence rows are stored for these session assessments.",
                    styles["FGBody"],
                )
            )
        else:
            story.append(
                _table(
                    evidence_rows,
                    widths=[18 * mm, 27 * mm, 51 * mm, 88 * mm],
                    font_size=6,
                )
            )

        story.extend(
            [
                Paragraph("Normal Activity Summary", styles["FGSection"]),
                Paragraph(_pdf_text(data["normal_summary"]), styles["FGBody"]),
                Paragraph("Forensic Timeline", styles["FGSection"]),
            ]
        )
        timeline_rows = [["Time", "Type", "Observed activity"]]
        timeline_rows.extend(
            [
                [
                    _timestamp_from_db(item["timestamp"]),
                    item["kind"],
                    item["description"],
                ]
                for item in data["timeline"]
            ]
        )
        if len(timeline_rows) == 1:
            timeline_rows.append(["-", "Session", "No session events recorded."])
        story.append(
            _table(
                timeline_rows,
                widths=[27 * mm, 23 * mm, 134 * mm],
                font_size=6,
            )
        )
        story.extend(
            [
                Paragraph(
                    "Forensic Analytical Summary",
                    styles["FGSection"],
                ),
                Paragraph(_pdf_text(data["analysis"]), styles["FGBody"]),
                Paragraph("Final Assessment", styles["FGSection"]),
                Paragraph(
                    f"Final risk score: {data['risk_score']} / 100; "
                    f"risk level: {data['risk_level']}.",
                    styles["FGBody"],
                ),
                Paragraph(_pdf_text(data["conclusion"]), styles["FGBody"]),
                Paragraph("Key Findings", styles["FGSection"]),
                *[
                    Paragraph(f"• {_pdf_text(item)}", styles["FGBody"])
                    for item in data["key_findings"]
                ],
                Paragraph("Recommended Actions", styles["FGSection"]),
                *[
                    Paragraph(f"• {_pdf_text(item)}", styles["FGBody"])
                    for item in data["recommendations"]
                ],
                Paragraph(
                    "Generated by ForensicGuard | Session "
                    f"{_pdf_text(data['session_id'])} | "
                    f"{_pdf_text(_timestamp(data['ended_at']))}<br/>"
                    "This report is based on telemetry available to ForensicGuard "
                    "during the monitored session.",
                    styles["FGSmall"],
                ),
            ]
        )
        document.build(
            story,
            onFirstPage=lambda canvas, doc: _draw_page_footer(canvas, doc, data),
            onLaterPages=lambda canvas, doc: _draw_page_footer(canvas, doc, data),
        )


def _table(rows: list[list[Any]], widths: list[float], font_size: float) -> Table:
    cell_style = ParagraphStyle(
        name=f"FGCell{font_size}",
        fontName="Helvetica",
        fontSize=font_size,
        leading=font_size + 1,
        spaceAfter=0,
    )
    rendered = [
        [Paragraph(_pdf_text(value), cell_style) for value in row]
        for row in rows
    ]
    table = Table(rendered, colWidths=widths, repeatRows=1 if len(rows) > 2 else 0)
    table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), font_size),
                ("LEADING", (0, 0), (-1, -1), font_size + 1),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8edf3")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#182230")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd2da")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )
    return table


def _event_category(event: dict[str, Any]) -> str:
    identity = " ".join(
        str(event.get(key) or "")
        for key in ("source", "event_id", "action", "details")
    ).lower()
    if "usb" in identity or "removable" in identity:
        return "usb"
    if "security" in identity or "login" in identity:
        return "security"
    if "file" in identity or "folder" in identity:
        return "file"
    return "other"


def _risk_level(value: Any) -> str:
    level = str(value or "LOW").strip().upper()
    return level if level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "UNKNOWN"


def _severity_rank(level: str) -> int:
    return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(level, -1)


def _timestamp_from_db(value: Any) -> str:
    return _bounded_text(value, 19) or "Unknown"


def _duration(start: datetime, end: datetime) -> str:
    seconds = max(0, int((end - start).total_seconds()))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def _event_matches_assessment(
    event: dict[str, Any], assessment: dict[str, Any]
) -> bool:
    event_id = str(event.get("event_id") or "").casefold()
    trigger_id = str(assessment.get("trigger_event_id") or "").casefold()
    source = str(event.get("source") or "").casefold()
    trigger_source = str(assessment.get("trigger_event_source") or "").casefold()
    event_application = str(event.get("application") or "").strip().casefold()
    trigger_application = str(
        assessment.get("trigger_application") or ""
    ).strip().casefold()
    event_time = _parse_timestamp(event.get("timestamp"))
    assessment_time = _parse_timestamp(assessment.get("timestamp"))
    within_trigger_window = (
        event_time is not None
        and assessment_time is not None
        and abs((event_time - assessment_time).total_seconds()) <= 2
    )
    return bool(
        event_id
        and trigger_id
        and event_id == trigger_id
        and (not trigger_source or trigger_source == source)
        and (not trigger_application or trigger_application == event_application)
        and within_trigger_window
    )


def _activity_counts(events: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "file_created": 0,
        "file_modified": 0,
        "file_deleted": 0,
        "file_renamed": 0,
        "file_moved": 0,
        "usb": 0,
        "file_transfer": 0,
        "security": 0,
        "other": 0,
        "total": len(events),
    }
    for event in events:
        event_id = str(event.get("event_id") or "").upper()
        action = str(event.get("action") or "").casefold()
        source = str(event.get("source") or "").casefold()
        if event_id == "FILE_CREATE":
            counts["file_created"] += 1
        elif event_id == "FILE_MODIFY":
            counts["file_modified"] += 1
        elif event_id == "FILE_DELETE":
            counts["file_deleted"] += 1
        elif event_id in {"FILE_RENAME", "FILE_MOVED", "FILE_MOVE"}:
            if event_id in {"FILE_MOVED", "FILE_MOVE"} or "moved" in action:
                counts["file_moved"] += 1
            else:
                counts["file_renamed"] += 1
        elif event_id == "FILE_COPY" or "file copied" in action:
            counts["file_transfer"] += 1
        elif "transfer" in event_id or "transfer" in action:
            counts["file_transfer"] += 1

        if event_id.startswith("USB") or "removable" in source:
            counts["usb"] += 1
        if "security" in source or event_id.startswith(("46", "47")):
            counts["security"] += 1
        elif not (
            event_id.startswith(("FILE_", "FOLDER_"))
            or event_id.startswith("USB")
            or "transfer" in event_id
            or "file copied" in action
        ):
            counts["other"] += 1
    return counts


def _official_rule_name(assessment: dict[str, Any]) -> str:
    rule_id = assessment.get("rule_id")
    if rule_id is not None:
        try:
            rule = get_rule(int(rule_id))
        except (TypeError, ValueError):
            rule = None
        if rule is not None:
            return rule.rule_name
        return f"Rule {rule_id} (not in official registry)"
    return "Triggered assessment (no rule ID)"


def _parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(text, pattern)
        except ValueError:
            continue
    return None


def _normal_activity_summary(
    observed: int,
    activity_counts: dict[str, int],
) -> str:
    if not observed:
        return (
            "No session event could be classified as unassociated with a "
            "triggered assessment from the stored correlation fields. This "
            "does not classify unobserved activity."
        )
    counts = ", ".join(
        f"{activity_counts[key]} {label}"
        for key, label in (
            ("file_created", "file created"),
            ("file_modified", "file modified"),
            ("file_deleted", "file deleted"),
            ("file_renamed", "file renamed"),
            ("file_moved", "file moved"),
            ("file_transfer", "file transfer"),
            ("usb", "USB/removable"),
            ("security", "security"),
            ("other", "other"),
        )
        if activity_counts[key]
    )
    return (
        f"{observed} observed event(s) had no matching stored triggered risk "
        f"assessment: "
        f"{counts}. These counts describe telemetry and do not certify the "
        f"activity as safe."
    )


def _timeline(
    events: list[dict[str, Any]],
    assessments: list[dict[str, Any]],
    evidence: dict[int, list[dict[str, Any]]],
    started_at: datetime,
    ended_at: datetime,
) -> list[dict[str, str]]:
    items: list[dict[str, Any]] = [
        {
            "timestamp": _timestamp(started_at),
            "kind": "SESSION START",
            "description": "Monitoring session started.",
            "priority": 0,
            "risk_score": 0,
        },
        {
            "timestamp": _timestamp(ended_at),
            "kind": "REPORT GENERATED",
            "description": "Session report generated.",
            "priority": 0,
            "risk_score": 0,
        },
    ]
    for assessment in assessments:
        rule_label = _official_rule_name(assessment)
        details = assessment.get("trigger_details") or assessment.get("evidence_summary")
        if not details:
            rows = evidence.get(int(assessment["id"]), [])
            details = rows[0].get("evidence_text") if rows else "Evidence recorded."
        items.append(
            {
                "timestamp": str(assessment.get("timestamp") or ""),
                "kind": "RISK",
                "description": _bounded_text(
                    f"{rule_label} - {_risk_level(assessment.get('risk_level'))} "
                    f"({assessment.get('risk_score')}/100): {details}",
                    220,
                ),
                "priority": 0,
                "risk_score": int(assessment.get("risk_score") or 0),
            }
        )

    significant_events = []
    for event in events:
        event_id = str(event.get("event_id") or "").upper()
        category = _event_category(event)
        if category in {"usb", "security"} or any(
            word in event_id for word in ("TRANSFER", "ALERT", "AUTH", "SECURITY")
        ):
            significant_events.append(event)
    for event in significant_events[:MAX_TIMELINE_ITEMS]:
        items.append(
            {
                "timestamp": str(event.get("timestamp") or ""),
                "kind": _event_category(event).upper(),
                "description": _bounded_text(
                    " ".join(
                        filter(
                            None,
                            [
                                str(event.get("action") or ""),
                                str(event.get("application") or ""),
                                str(event.get("details") or ""),
                            ],
                        )
                    ),
                    220,
                ),
                "priority": 0,
                "risk_score": 0,
            }
        )

    file_events = [event for event in events if _event_category(event) == "file"]
    if file_events:
        counts = Counter(str(event.get("event_id") or "File activity") for event in file_events)
        description = ", ".join(
            f"{name}: {count}" for name, count in counts.most_common(6)
        )
        items.append(
            {
                "timestamp": str(file_events[-1].get("timestamp") or ""),
                "kind": "FILE SUMMARY",
                "description": _bounded_text(
                    f"{len(file_events)} observed file/folder event(s); {description}",
                    220,
                ),
                "priority": 2,
                "risk_score": 0,
            }
        )

    items.sort(
        key=lambda item: (
            item["priority"],
            -item["risk_score"],
            item["timestamp"],
        )
    )
    selected = items[:MAX_TIMELINE_ITEMS]
    selected.sort(key=lambda item: (item["timestamp"], item["kind"]))
    return [
        {
            key: value
            for key, value in item.items()
            if key not in {"priority", "risk_score"}
        }
        for item in selected
    ]


def _analysis(
    assessments: list[dict[str, Any]],
    events: list[dict[str, Any]],
    risk_level: str,
) -> str:
    counts = _activity_counts(events)
    activity_summary = ", ".join(
        f"{counts[key]} {label}"
        for key, label in (
            ("file_created", "file creation"),
            ("file_modified", "file modification"),
            ("file_deleted", "file deletion"),
            ("file_renamed", "file rename"),
            ("file_moved", "file move"),
            ("file_transfer", "file transfer"),
            ("usb", "USB/removable"),
            ("security", "security"),
        )
        if counts[key]
    )
    observed_text = (
        f"Observed event counts include {activity_summary}."
        if activity_summary
        else "No categorized file, transfer, USB, or security event was recorded."
    )
    if not assessments:
        return (
            f"The session contains {len(events)} recorded event(s), and no "
            "supported suspicious rule was triggered in the session-scoped risk "
            f"assessments. {observed_text} This is not a guarantee that all "
            "activity was safe. "
            "Review the observed events if they require operational context."
        )

    rules = Counter(
        _official_rule_name(row)
        for row in assessments
        if row.get("rule_id") is not None
    )
    top_rules = ", ".join(name for name, _ in rules.most_common(4))
    distinct = len(rules)
    text = (
        f"The session contains {len(events)} recorded event(s) and "
        f"{len(assessments)} qualifying triggered assessment(s) across "
        f"{distinct} distinct rule(s). The highest stored session risk level is "
        f"{risk_level}. {observed_text}"
    )
    if top_rules:
        text += f" The most frequently represented detected rule(s): {top_rules}."
        explanations = []
        for assessment in assessments:
            rule_id = assessment.get("rule_id")
            if rule_id is None:
                continue
            rule = get_rule(int(rule_id))
            if rule is not None and rule.short_description not in explanations:
                explanations.append(rule.short_description)
            if len(explanations) == 3:
                break
        if explanations:
            text += " Registry descriptions: " + " ".join(explanations)
    rule_names = " ".join(rules).lower()
    correlations = []
    if any(token in rule_names for token in ("transfer", "external", "upload", "usb")):
        correlations.append("transfer-related indicators were recorded")
    if any(token in rule_names for token in ("mass file", "mass folder", "rapid rename")):
        correlations.append("high-volume file/folder or rename indicators were recorded")
    if correlations:
        text += " Observed correlations: " + "; ".join(correlations) + "."
    rule_ids = {
        int(row["rule_id"])
        for row in assessments
        if row.get("rule_id") is not None
    }
    rule_times = [
        _parse_timestamp(row.get("timestamp"))
        for row in assessments
        if row.get("rule_id") is not None
    ]
    rule_times = [value for value in rule_times if value is not None]
    temporally_correlated = (
        len(rule_ids) > 1
        and any(
            abs((left - right).total_seconds()) <= 10 * 60
            for index, left in enumerate(rule_times)
            for right in rule_times[index + 1:]
        )
    )
    if len(rule_ids) > 1:
        if temporally_correlated:
            text += (
                " Distinct rule detections fall within a 10-minute window; "
                "this is temporal correlation, not proof of causation."
            )
        else:
            text += (
                " No supported cross-rule temporal correlation was identified."
            )
    else:
        text += (
            " The stored session data does not support a multi-rule correlation."
        )
    if len(assessments) > distinct:
        text += (
            f" There were {len(assessments)} triggered assessment row(s), "
            f"including repeated detections of some rule(s)."
        )
    text += (
        " These statements are limited to stored session telemetry and rule "
        "evidence; investigate the cited records and source files before taking "
        "containment action."
    )
    return text


def _final_assessment(level: str, assessments: list[dict[str, Any]]) -> str:
    recommendations = {
        "LOW": "No significant suspicious rule activity was detected in the available session data; retain the report and review observed events as needed.",
        "MEDIUM": "Potentially suspicious activity was detected; review the cited rules and evidence.",
        "HIGH": "High-risk indicators were detected; further forensic investigation is recommended.",
        "CRITICAL": "Critical indicators were detected; prioritize investigation and follow incident-response procedures.",
    }
    if not assessments:
        return (
            "No supported suspicious rule was triggered during this session. "
            "The report reflects available telemetry and does not establish "
            "that the system is completely safe."
        )
    return recommendations.get(level, "Review the available session evidence.")


def _highest_activity_label(assessment: dict[str, Any] | None) -> str:
    if assessment is None:
        return "No qualifying risk assessment stored"
    rule_id = assessment.get("rule_id")
    if rule_id is not None:
        return _official_rule_name(assessment)
    return str(assessment.get("activity_type") or "Triggered risk assessment")


def _key_findings(
    assessments: list[dict[str, Any]], activity_counts: dict[str, int]
) -> list[str]:
    findings = [
        f"{activity_counts['total']} monitored event(s) were recorded during the session."
    ]
    if not assessments:
        findings.append("No session-scoped triggered risk assessment was stored.")
        return findings
    findings.append(
        f"{len(assessments)} triggered assessment(s) were stored at "
        f"the corresponding rule/event level."
    )
    rule_names = sorted(
        {
            _official_rule_name(row)
            for row in assessments
            if row.get("rule_id") is not None
        }
    )
    if rule_names:
        findings.append("Detected rule(s): " + "; ".join(rule_names[:5]) + ".")
    return findings


def _recommendations(
    risk_level: str, assessments: list[dict[str, Any]]
) -> list[str]:
    if not assessments:
        return [
            "No rule-based assessment requires escalation from this report; review observed telemetry when additional context is needed."
        ]
    actions = {
        "LOW": "Retain the report and review any events requiring additional context.",
        "MEDIUM": "Review the cited rule detections and their associated evidence.",
        "HIGH": "Investigate the high-risk indicators and preserve related evidence.",
        "CRITICAL": "Prioritize incident response and preserve relevant evidence.",
    }
    return [actions.get(risk_level, "Review the available session evidence.")]


def _draw_page_footer(canvas: Any, document: Any, data: dict[str, Any]) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 6)
    canvas.setFillColor(colors.HexColor("#52606d"))
    canvas.drawString(
        document.leftMargin,
        6 * mm,
        f"ForensicGuard | Report {data['report_id']}",
    )
    canvas.drawRightString(
        A4[0] - document.rightMargin,
        6 * mm,
        f"{_timestamp(data['ended_at'])} | Page {document.page}",
    )
    canvas.restoreState()
