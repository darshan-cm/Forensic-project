import getpass
import socket
from datetime import datetime
from pathlib import Path

import sqlite3

from detection.rule_registry import get_rule, get_rule_by_name

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None


DB_PATH = Path(__file__).with_name("riskalert.db")
FORENSIC_DB_PATH = Path(__file__).with_name("forensic.db")


def _normalize_rule(rule_id=None, rule_name=None):
    """Validate optional official-rule metadata without inventing a rule."""

    if rule_id is None and rule_name is None:
        return None, None

    if rule_id is not None:
        try:
            normalized_id = int(rule_id)
        except (TypeError, ValueError):
            raise ValueError(f"rule_id must be an integer, got: {rule_id!r}")

        rule = get_rule(normalized_id)
        if rule is None:
            raise ValueError(f"Unsupported rule_id: {normalized_id}")

        normalized_name = rule.rule_name
        if rule_name is not None and str(rule_name).strip() != normalized_name:
            raise ValueError(
                f"rule_name '{rule_name}' does not match rule_id {normalized_id} "
                f"({normalized_name})."
            )

        return normalized_id, normalized_name

    normalized_name = str(rule_name).strip()
    rule = get_rule_by_name(normalized_name)
    if rule is None:
        raise ValueError(f"Unsupported rule_name: {rule_name!r}")

    return rule.rule_id, rule.rule_name


def _ensure_risk_assessment_columns(conn):
    """Safely add missing columns to an existing risk_assessments table."""

    try:
        columns = conn.execute("PRAGMA table_info(risk_assessments)").fetchall()
    except sqlite3.DatabaseError:
        return

    existing_fields = {row[1] for row in columns}
    required_columns = {
        "ml_prediction": "TEXT",
        "ml_attack_probability": "REAL",
        "ml_benign_probability": "REAL",
        "trigger_event_id": "TEXT",
        "trigger_event_source": "TEXT",
        "trigger_application": "TEXT",
        "trigger_details": "TEXT",
        "rule_id": "INTEGER",
        "rule_name": "TEXT",
        "evidence_summary": "TEXT",
        "username": "TEXT",
        "hostname": "TEXT",
        "process_name": "TEXT",
        "process_id": "INTEGER",
        "window_title": "TEXT",
        "notification_triggered": "INTEGER DEFAULT 0",
        "notification_timestamp": "TEXT",
        "notification_status": "TEXT",
        "alert_message": "TEXT",
    }

    for field_name, field_definition in required_columns.items():
        if field_name not in existing_fields:
            conn.execute(
                f"ALTER TABLE risk_assessments ADD COLUMN {field_name} {field_definition}"
            )


def initialize_riskalert_db():
    """Create the risk audit database and required indexes."""

    conn = sqlite3.connect(DB_PATH)

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS risk_assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                ml_prediction TEXT,
                ml_attack_probability REAL,
                ml_benign_probability REAL,
                activity_type TEXT,
                trigger_event_id TEXT,
                trigger_event_source TEXT,
                trigger_application TEXT,
                trigger_details TEXT,
                rule_id INTEGER,
                rule_name TEXT,
                evidence_summary TEXT,
                username TEXT,
                hostname TEXT,
                process_name TEXT,
                process_id INTEGER,
                window_title TEXT,
                notification_triggered INTEGER DEFAULT 0,
                notification_timestamp TEXT,
                notification_status TEXT,
                alert_message TEXT
            )
            """
        )

        _ensure_risk_assessment_columns(conn)

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS risk_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                risk_id INTEGER NOT NULL,
                evidence_text TEXT,
                event_id TEXT,
                event_source TEXT,
                application TEXT,
                details TEXT,
                file_path TEXT,
                source_path TEXT,
                destination_path TEXT,
                usb_device TEXT,
                process_name TEXT,
                process_id INTEGER,
                content_type TEXT,
                content_length INTEGER,
                content_hash TEXT,
                FOREIGN KEY (risk_id) REFERENCES risk_assessments(id)
            )
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_risk_assessments_timestamp
            ON risk_assessments (timestamp)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_risk_assessments_level
            ON risk_assessments (risk_level)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_risk_assessments_notification
            ON risk_assessments (notification_triggered)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_risk_assessments_rule_id
            ON risk_assessments (rule_id)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_risk_evidence_risk_id
            ON risk_evidence (risk_id)
            """
        )

        conn.commit()

    finally:
        conn.close()


def _safe_text(value):
    if value is None:
        return None

    text = str(value).strip()

    return text or None


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _get_context():
    username = None
    hostname = None
    process_name = None
    process_id = None
    window_title = None

    try:
        username = getpass.getuser()
    except Exception:
        username = None

    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = None

    if psutil is not None:
        try:
            current = psutil.Process()
            process_name = _safe_text(current.name())
            process_id = current.pid
        except Exception:
            process_name = None
            process_id = None

    return {
        "username": username,
        "hostname": hostname,
        "process_name": process_name,
        "process_id": process_id,
        "window_title": window_title,
    }


def _determine_activity_type(risk_result):
    if not isinstance(risk_result, dict):
        return "OTHER"

    if risk_result.get("security_events", 0):
        return "CREDENTIAL_ACTIVITY"

    if risk_result.get("usb_connections", 0) and risk_result.get("files_copied", 0):
        return "USB_TRANSFER"

    if risk_result.get("files_copied", 0):
        return "FILE_COPY"

    if risk_result.get("usb_connections", 0):
        return "USB_INSERT"

    if risk_result.get("transfer_status"):
        return "OTHER"

    return "OTHER"


def _parse_event_details(details):
    if not details:
        return {}

    result = {}
    for part in str(details).split(" | "):
        if "=" not in part:
            continue

        key, value = part.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key and value:
            result[key] = value

    return result


def _load_recent_forensic_context():
    try:
        conn = sqlite3.connect(FORENSIC_DB_PATH)
        cursor = conn.cursor()
        rows = cursor.execute(
            """
            SELECT timestamp, source, event_id, action, application, details
            FROM events
            ORDER BY id DESC
            LIMIT 200
            """
        ).fetchall()
        conn.close()
    except Exception:
        return {}

    latest = {}

    for timestamp, source, event_id, action, application, details in rows:
        event_id_text = str(event_id or "").strip()
        if not event_id_text:
            continue

        parsed = _parse_event_details(details)

        if event_id_text == "FILE_COPY":
            latest["FILE_COPY"] = {
                "timestamp": timestamp,
                "source": source,
                "event_id": event_id_text,
                "action": action,
                "application": application,
                "details": details,
                "file_count": parsed.get("FileCount"),
                "total_size": parsed.get("TotalSize"),
                "files": parsed.get("Files"),
            }

        elif event_id_text == "USB_FILE_TRANSFER":
            latest["USB_FILE_TRANSFER"] = {
                "timestamp": timestamp,
                "source": source,
                "event_id": event_id_text,
                "action": action,
                "application": application,
                "details": details,
                "source_path": parsed.get("Source"),
                "destination_path": parsed.get("Destination"),
                "device": parsed.get("Device"),
                "status": parsed.get("Status"),
                "file_name": parsed.get("File"),
                "file_size": parsed.get("Size"),
            }

        elif event_id_text == "MTP_TRANSFER_ATTEMPTED":
            latest["MTP_TRANSFER_ATTEMPTED"] = {
                "timestamp": timestamp,
                "source": source,
                "event_id": event_id_text,
                "action": action,
                "application": application,
                "details": details,
                "device": parsed.get("Device"),
                "destination": parsed.get("Destination"),
                "file_count": parsed.get("FileCount"),
                "total_size": parsed.get("TotalSize"),
                "status": parsed.get("Status"),
            }

        elif event_id_text == "USB_CONNECTED":
            latest["USB_CONNECTED"] = {
                "timestamp": timestamp,
                "source": source,
                "event_id": event_id_text,
                "action": action,
                "application": application,
                "details": details,
            }

    return latest


def record_risk_evidence(
    risk_id,
    evidence_text,
    event_id=None,
    event_source=None,
    application=None,
    details=None,
    file_path=None,
    source_path=None,
    destination_path=None,
    usb_device=None,
    process_name=None,
    process_id=None,
    content_type=None,
    content_length=None,
    content_hash=None,
):
    """Persist a single evidence item for a risk record."""

    if risk_id is None:
        return None

    conn = sqlite3.connect(DB_PATH)

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO risk_evidence (
                risk_id,
                evidence_text,
                event_id,
                event_source,
                application,
                details,
                file_path,
                source_path,
                destination_path,
                usb_device,
                process_name,
                process_id,
                content_type,
                content_length,
                content_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                risk_id,
                _safe_text(evidence_text),
                _safe_text(event_id),
                _safe_text(event_source),
                _safe_text(application),
                _safe_text(details),
                _safe_text(file_path),
                _safe_text(source_path),
                _safe_text(destination_path),
                _safe_text(usb_device),
                _safe_text(process_name),
                _safe_int(process_id),
                _safe_text(content_type),
                _safe_int(content_length),
                _safe_text(content_hash),
            ),
        )

        conn.commit()
        return cursor.lastrowid

    except Exception as error:
        print(f"[Risk Audit DB] Evidence save failed: {error}")
        return None

    finally:
        conn.close()


def record_risk_assessment(
    risk_result,
    notification_triggered=False,
    notification_status=None,
    alert_message=None,
    trigger_event_id=None,
    trigger_event_source=None,
    trigger_application=None,
    trigger_details=None,
    process_name=None,
    process_id=None,
    window_title=None,
    rule_id=None,
    rule_name=None,
):
    """Record a single risk assessment into the audit database."""

    initialize_riskalert_db()

    if not isinstance(risk_result, dict):
        risk_result = {}

    normalized_rule_id, normalized_rule_name = _normalize_rule(rule_id, rule_name)

    context = _get_context()
    forensic_context = _load_recent_forensic_context()

    trigger_event = forensic_context.get("USB_FILE_TRANSFER") or forensic_context.get("MTP_TRANSFER_ATTEMPTED") or forensic_context.get("FILE_COPY") or forensic_context.get("USB_CONNECTED")

    risk_level = str(risk_result.get("risk", "LOW") or "LOW").upper()
    risk_score = _safe_int(risk_result.get("score", 0)) or 0

    evidence_items = risk_result.get("evidence") or []
    if isinstance(evidence_items, str):
        evidence_items = [evidence_items]

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    evidence_summary = " | ".join(str(item) for item in evidence_items if item)

    ml_prediction = _safe_text(risk_result.get("ml_prediction"))
    attack_probability = _safe_float(risk_result.get("attack_probability"))
    benign_probability = _safe_float(risk_result.get("benign_probability"))

    if notification_status is None:
        if notification_triggered:
            notification_status = "sent"
        else:
            notification_status = "not_required"

    if risk_level in ("HIGH", "CRITICAL") and not notification_triggered:
        notification_status = "suppressed"

    if alert_message is None:
        if risk_level in ("HIGH", "CRITICAL"):
            alert_message = f"{risk_level} risk detected. Score: {risk_score}/100."
        else:
            alert_message = None

    source_path = None
    destination_path = None
    usb_device = None
    file_path = None

    if trigger_event:
        trigger_event_id = trigger_event_id or trigger_event.get("event_id")
        trigger_event_source = trigger_event_source or trigger_event.get("source")
        trigger_application = trigger_application or trigger_event.get("application")
        trigger_details = trigger_details or trigger_event.get("details")

        if not process_name and trigger_event.get("source"):
            process_name = trigger_event.get("source")

        source_path = trigger_event.get("source_path") or source_path
        destination_path = trigger_event.get("destination_path") or destination_path
        usb_device = trigger_event.get("device") or usb_device
        file_path = trigger_event.get("file_name") or trigger_event.get("files") or file_path

    notification_timestamp = None
    if notification_triggered:
        notification_timestamp = timestamp

    conn = sqlite3.connect(DB_PATH)

    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO risk_assessments (
                timestamp,
                risk_level,
                risk_score,
                ml_prediction,
                ml_attack_probability,
                ml_benign_probability,
                activity_type,
                trigger_event_id,
                trigger_event_source,
                trigger_application,
                trigger_details,
                rule_id,
                rule_name,
                evidence_summary,
                username,
                hostname,
                process_name,
                process_id,
                window_title,
                notification_triggered,
                notification_timestamp,
                notification_status,
                alert_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                risk_level,
                risk_score,
                ml_prediction,
                attack_probability,
                benign_probability,
                _determine_activity_type(risk_result),
                _safe_text(trigger_event_id),
                _safe_text(trigger_event_source),
                _safe_text(trigger_application or risk_result.get("application")),
                _safe_text(trigger_details or risk_result.get("transfer_status")),
                _safe_int(normalized_rule_id),
                _safe_text(normalized_rule_name),
                evidence_summary or None,
                _safe_text(context.get("username")),
                _safe_text(context.get("hostname")),
                _safe_text(process_name or context.get("process_name")),
                _safe_int(process_id if process_id is not None else context.get("process_id")),
                _safe_text(window_title),
                1 if notification_triggered else 0,
                notification_timestamp,
                _safe_text(notification_status),
                _safe_text(alert_message),
            ),
        )

        risk_id = cursor.lastrowid

        for evidence_text in evidence_items:
            if evidence_text is None:
                continue

            cursor.execute(
                """
                INSERT INTO risk_evidence (
                    risk_id,
                    evidence_text,
                    event_id,
                    event_source,
                    application,
                    details,
                    file_path,
                    source_path,
                    destination_path,
                    usb_device,
                    process_name,
                    process_id,
                    content_type,
                    content_length,
                    content_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    risk_id,
                    str(evidence_text),
                    _safe_text(trigger_event_id),
                    _safe_text(trigger_event_source),
                    _safe_text(trigger_application or risk_result.get("application")),
                    _safe_text(trigger_details or risk_result.get("transfer_status")),
                    _safe_text(file_path),
                    _safe_text(source_path),
                    _safe_text(destination_path),
                    _safe_text(usb_device),
                    _safe_text(process_name or context.get("process_name")),
                    _safe_int(process_id if process_id is not None else context.get("process_id")),
                    None,
                    None,
                    None,
                ),
            )

        conn.commit()
        return risk_id

    except Exception as error:
        print(f"[Risk Audit DB] Risk save failed: {error}")
        return None

    finally:
        conn.close()


def get_recent_risk_history(limit=20):
    initialize_riskalert_db()

    conn = sqlite3.connect(DB_PATH)

    try:
        rows = conn.execute(
            """
            SELECT
                id,
                timestamp,
                risk_level,
                risk_score,
                activity_type,
                evidence_summary,
                notification_triggered,
                notification_status,
                alert_message
            FROM risk_assessments
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        return rows

    finally:
        conn.close()


initialize_riskalert_db()
