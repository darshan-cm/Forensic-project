import time
import win32evtlog

from database.database import insert_event


EVENTS = {
    4688: "Process Created",
    4689: "Process Ended",
    4624: "Successful Login",
    4625: "Failed Login",
    4634: "User Logoff"
}


def security_monitor():

    print("[Security Monitor] Started...\n")

    server = "localhost"
    log_type = "Security"

    hand = win32evtlog.OpenEventLog(server, log_type)

    # Skip all old events
    last_record = win32evtlog.GetNumberOfEventLogRecords(hand)

    flags = (
        win32evtlog.EVENTLOG_FORWARDS_READ |
        win32evtlog.EVENTLOG_SEQUENTIAL_READ
    )

    while True:

        events = win32evtlog.ReadEventLog(
            hand,
            flags,
            0
        )

        if events:

            for event in events:

                if event.RecordNumber <= last_record:
                    continue

                last_record = event.RecordNumber

                event_id = event.EventID & 0xFFFF

                if event_id not in EVENTS:
                    continue

                print("\n" + "=" * 70)
                print("SECURITY EVENT")
                print("=" * 70)
                print(f"Event ID : {event_id}")
                print(f"Action   : {EVENTS[event_id]}")
                print(f"Time     : {event.TimeGenerated}")

                details = ""

                if event.StringInserts:

                    details = " | ".join(event.StringInserts)

                    print("\nDetails:")
                    print(details)

                insert_event(
                    source="Security Log",
                    event_id=str(event_id),
                    action=EVENTS[event_id],
                    application="Windows",
                    details=details
                )

        time.sleep(1)