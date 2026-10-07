import sys
from datetime import datetime
from database.database import insert_event


def _configure_console_encoding():
    stream = sys.stdout
    reconfigure = getattr(stream, "reconfigure", None)
    if not callable(reconfigure):
        return
    try:
        reconfigure(encoding="utf-8", errors="backslashreplace")
    except (OSError, ValueError):
        pass


_configure_console_encoding()


def _write_console(message):
    stream = sys.stdout
    try:
        stream.write(message)
    except UnicodeEncodeError:
        encoding = getattr(stream, "encoding", None) or "ascii"
        escaped_message = message.encode(
            encoding, errors="backslashreplace"
        ).decode(encoding)
        stream.write(escaped_message)


def _sanitize_text(value):
    if value is None:
        return ""

    text = str(value)
    hidden_chars = {
        "\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"
    }

    cleaned = "".join(
        ch for ch in text
        if ch not in hidden_chars and (ord(ch) >= 32 or ch in "\n\r\t")
    )

    return cleaned.strip()


def log_event(source, event_id, action, application, details=""):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    application = _sanitize_text(application)
    details = _sanitize_text(details)
    source = _sanitize_text(source)
    event_id = _sanitize_text(event_id)
    action = _sanitize_text(action)

    output = [
        "",
        "=" * 80,
        f"TIME        : {timestamp}",
        f"SOURCE      : {source}",
        f"EVENT ID    : {event_id}",
        f"ACTION      : {action}",
        f"APPLICATION : {application}",
    ]

    if details:
        output.append(f"DETAILS     : {details}")

    output.append("=" * 80)
    _write_console("\n".join(output) + "\n")

    # Store event to operational database
    event_row_id = insert_event(
        source,
        event_id,
        action,
        application,
        details
    )

    session_id = None
    try:
        from reports.session_context import active_session_id, record_event

        session_id = active_session_id()
        if session_id is not None and event_row_id is not None:
            record_event(session_id, event_row_id)
    except Exception as error:
        _write_console(f"[Forensic Session] Event association failed: {error}\n")
    
    # Publish event to event engine for processing (e.g., risk assessment)
    try:
        from event_engine.engine import publish
        
        event_dict = {
            "timestamp": timestamp,
            "source": source,
            "event_id": event_id,
            "action": action,
            "application": application,
            "details": details,
            "session_id": session_id,
            "forensic_event_row_id": event_row_id,
        }
        publish(event_dict)
    except Exception as error:
        # Silently fail if event engine is not available
        # to prevent monitoring from breaking due to integration issues
        pass