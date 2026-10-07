from datetime import datetime
from database.database import insert_event


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

    print("\n" + "=" * 80)
    print(f"TIME        : {timestamp}")
    print(f"SOURCE      : {source}")
    print(f"EVENT ID    : {event_id}")
    print(f"ACTION      : {action}")
    print(f"APPLICATION : {application}")

    if details:
        print(f"DETAILS     : {details}")

    print("=" * 80)

    # Store event to operational database
    insert_event(
        source,
        event_id,
        action,
        application,
        details
    )
    
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
        }
        publish(event_dict)
    except Exception as error:
        # Silently fail if event engine is not available
        # to prevent monitoring from breaking due to integration issues
        pass