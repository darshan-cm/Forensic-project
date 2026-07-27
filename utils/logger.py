from datetime import datetime
from database.database import insert_event


def log_event(source, event_id, action, application, details=""):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n" + "═" * 80)
    print(f"TIME        : {timestamp}")
    print(f"SOURCE      : {source}")
    print(f"EVENT ID    : {event_id}")
    print(f"ACTION      : {action}")
    print(f"APPLICATION : {application}")

    if details:
        print(f"DETAILS     : {details}")

    print("═" * 80)

    insert_event(
        source,
        event_id,
        action,
        application,
        details
    )