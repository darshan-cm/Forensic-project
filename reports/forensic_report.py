"""Session-scoped, offline PDF reports built from existing telemetry."""

from __future__ import annotations

import os
import re
import sqlite3
import uuid
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
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
    Spacer,
    Table,
    TableStyle,
)

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


def _authenticated_user_id(user: Any) -> str | None:
    if user is None:
        return None
    value = user.get("id") if isinstance(user, dict) else getattr(user, "id", None)
    if value is None:
        return None
    identifier = str(value).strip()
    return identifier[:200] or None


def _timestamp(value: datetime) -> str:
    return value.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _bounded_text(value: Any, limit: int = MAX_TEXT_LENGTH) -> str:
    if value is None:
        return ""
    text = re.sub(r"\s+", " ", str(value)).strip()
    return text[:limit] + ("..." if len(text) > limit else "")


def _pdf_text(value: Any) -> str:
    text = _bounded_text(value, 1200)
    return escape(text.encode("latin-1", "replace").decode("latin-1"))


@dataclass
class ForensicSession:
    """In-memory boundaries and database high-water marks for one login."""

    user_id: str | None = None
    forensic_db_path: Path = FORENSIC_DB_PATH
    risk_db_path: Path = RISK_DB_PATH
    report_directory: Path = REPORT_DIRECTORY
    started_at: datetime = field(default_factory=lambda: datetime.now().astimezone())
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    initial_event_id: int = field(init=False)
    initial_assessment_id: int = field(init=False)

    def __post_init__(self) -> None:
        self.forensic_db_path = Path(self.forensic_db_path)
        self.risk_db_path = Path(self.risk_db_path)
        self.report_directory = Path(self.report_directory)
        self.initial_event_id = self._latest_id(
            self.forensic_db_path, "events"
        )
        self.initial_assessment_id = self._latest_id(
            self.risk_db_path, "risk_assessments"
        )

    @classmethod
    def start(
        cls,
        user: Any,
        *,
        forensic_db_path: Path = FORENSIC_DB_PATH,
        risk_db_path: Path = RISK_DB_PATH,
        report_directory: Path = REPORT_DIRECTORY,
    ) -> "ForensicSession":
        return cls(
            user_id=_authenticated_user_id(user),
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

    def generate_report(self, report_time: datetime | None = None) -> Path:
        end_time = report_time or datetime.now().astimezone()
        if end_time < self.started_at:
            raise ValueError("Report time cannot precede the session start.")

        events = self._session_events(end_time)
        assessments = self._session_assessments(end_time)
        evidence = self._session_evidence(assessments)
        report_data = self._build_report_data(
            end_time, events, assessments, evidence
        )

        self.report_directory.mkdir(parents=True, exist_ok=True)
        generated_stamp = end_time.strftime("%Y%m%d_%H%M%S_%f")
        filename = (
            f"ForensicGuard_{self.session_id}_{generated_stamp}.pdf"
        )
        destination = self.report_directory / filename
        temporary_path = destination.with_suffix(".pdf.tmp")
        try:
            self._write_pdf(temporary_path, report_data)
            self._verify_pdf(temporary_path)
            os.replace(temporary_path, destination)
            self._verify_pdf(destination)
        except Exception:
            if temporary_path.exists():
                temporary_path.unlink()
            raise
        return destination

    def _session_events(self, end_time: datetime) -> list[dict[str, Any]]:
        with _read_connection(self.forensic_db_path) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT id, timestamp, source, event_id, action, application, details
                FROM events
                WHERE id > ? AND timestamp >= ? AND timestamp <= ?
                ORDER BY id
                """,
                (
                    self.initial_event_id,
                    _timestamp(self.started_at),
                    _timestamp(end_time),
                ),
            ).fetchall()
        return [dict(row) for row in rows]

    def _session_assessments(
        self, end_time: datetime
    ) -> list[dict[str, Any]]:
        with _read_connection(self.risk_db_path) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT id, timestamp, risk_level, risk_score, activity_type,
                       trigger_event_id, trigger_event_source, trigger_application,
                       trigger_details, rule_id, rule_name, evidence_summary,
                       alert_message
                FROM risk_assessments
                WHERE id > ? AND timestamp >= ? AND timestamp <= ?
                  AND (trigger_event_id IS NOT NULL OR rule_id IS NOT NULL)
                ORDER BY id
                """,
                (
                    self.initial_assessment_id,
                    _timestamp(self.started_at),
                    _timestamp(end_time),
                ),
            ).fetchall()
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
                SELECT risk_id, evidence_text, event_id, event_source, details,
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
    ) -> dict[str, Any]:
        categories = Counter(_event_category(event) for event in events)
        scores = [
            (int(row["risk_score"]), _risk_level(row["risk_level"]))
            for row in assessments
            if row.get("risk_score") is not None
        ]
        highest_score, risk_level = max(
            scores,
            key=lambda item: (item[0], _severity_rank(item[1])),
            default=(0, "LOW"),
        )
        distinct_rules = {
            row.get("rule_id") or row.get("rule_name")
            for row in assessments
            if row.get("rule_id") is not None or row.get("rule_name")
        }
        unassociated_events = [
            event
            for event in events
            if not any(
                _event_matches_assessment(event, assessment)
                for assessment in assessments
            )
        ]
        normal_categories = Counter(
            _event_category(event) for event in unassociated_events
        )
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "started_at": self.started_at,
            "ended_at": end_time,
            "events": events,
            "assessments": assessments,
            "evidence": evidence,
            "categories": categories,
            "risk_score": highest_score,
            "risk_level": risk_level,
            "distinct_rules": distinct_rules,
            "timeline": _timeline(events, assessments, evidence),
            "normal_summary": _normal_activity_summary(
                normal_categories, len(unassociated_events)
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
            Paragraph("Session Forensic Report", styles["FGSection"]),
            Paragraph(
                f"Report generated: {_pdf_text(_timestamp(data['ended_at']))}",
                styles["FGBody"],
            ),
            Paragraph("Session Information", styles["FGSection"]),
            _table(
                [
                    ["Session ID", data["session_id"]],
                    ["User identifier", data["user_id"] or "Not available"],
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
                    ["File activity", str(data["categories"]["file"])],
                    ["USB activity", str(data["categories"]["usb"])],
                    ["Security events", str(data["categories"]["security"])],
                    ["Other monitored activity", str(data["categories"]["other"])],
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
                    ["Distinct rules triggered", str(len(data["distinct_rules"]))],
                    ["Highest assessment score", f"{data['risk_score']} / 100"],
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
                    "AI-Assisted / Rule-Based Forensic Analysis",
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
        document.build(story)


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
    return bool(
        event_id
        and trigger_id
        and event_id == trigger_id
        and (not trigger_source or trigger_source == source)
    )


def _normal_activity_summary(
    categories: Counter[str], observed: int
) -> str:
    if not observed:
        return (
            "No session events remained after correlating events with triggered "
            "risk assessments; this does not classify unobserved activity."
        )
    counts = ", ".join(
        f"{categories[label]} {label} event(s)"
        for label in ("file", "usb", "security", "other")
        if categories[label]
    )
    return (
        f"{observed} observed event(s) were not matched to a triggered risk "
        f"assessment: "
        f"{counts}. These counts describe telemetry and do not certify the "
        f"activity as safe."
    )


def _timeline(
    events: list[dict[str, Any]],
    assessments: list[dict[str, Any]],
    evidence: dict[int, list[dict[str, Any]]],
) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for assessment in assessments:
        rule_label = (
            f"Rule {assessment['rule_id']}: {assessment['rule_name']}"
            if assessment.get("rule_id") is not None
            else str(assessment.get("activity_type") or "Risk assessment")
        )
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
                "priority": "0",
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
                "priority": "1",
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
                "priority": "2",
            }
        )

    items.sort(key=lambda item: (item["priority"], item["timestamp"]))
    return [
        {key: value for key, value in item.items() if key != "priority"}
        for item in items[:MAX_TIMELINE_ITEMS]
    ]


def _analysis(
    assessments: list[dict[str, Any]],
    events: list[dict[str, Any]],
    risk_level: str,
) -> str:
    if not assessments:
        return (
            f"The session contains {len(events)} recorded event(s), and no "
            "supported suspicious rule was triggered in the session-scoped risk "
            "assessments. This is not a guarantee that all activity was safe. "
            "Review the observed events if they require operational context."
        )

    rules = Counter(
        f"Rule {row['rule_id']}: {row['rule_name']}"
        for row in assessments
        if row.get("rule_id") is not None
    )
    top_rules = ", ".join(name for name, _ in rules.most_common(4))
    distinct = len(rules)
    text = (
        f"The session contains {len(events)} recorded event(s) and "
        f"{len(assessments)} qualifying triggered assessment(s) across "
        f"{distinct} distinct rule(s). The highest stored session risk level is "
        f"{risk_level}."
    )
    if top_rules:
        text += f" The most frequently represented detected rule(s): {top_rules}."
    rule_names = " ".join(rules).lower()
    correlations = []
    if any(token in rule_names for token in ("transfer", "external", "upload", "usb")):
        correlations.append("transfer-related indicators were recorded")
    if any(token in rule_names for token in ("mass file", "mass folder", "rapid rename")):
        correlations.append("high-volume file/folder or rename indicators were recorded")
    if correlations:
        text += " Observed correlations: " + "; ".join(correlations) + "."
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
