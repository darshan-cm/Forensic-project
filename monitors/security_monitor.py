# import time
# import win32evtlog

# from database.database import insert_event


# EVENTS = {
#     4688: "Process Created",
#     4689: "Process Ended",
#     4624: "Successful Login",
#     4625: "Failed Login",
#     4634: "User Logoff"
# }


# def security_monitor():

#     print("[Security Monitor] Started...\n")

#     server = "localhost"
#     log_type = "Security"

#     hand = win32evtlog.OpenEventLog(server, log_type)

#     # Skip all old events
#     # last_record = win32evtlog.GetNumberOfEventLogRecords(hand)
#     last_record = win32evtlog.GetOldestEventLogRecord(hand) + \
#               win32evtlog.GetNumberOfEventLogRecords(hand) - 1

#     flags = (
#         win32evtlog.EVENTLOG_FORWARDS_READ |
#         win32evtlog.EVENTLOG_SEQUENTIAL_READ
#     )

#     while True:

#         events = win32evtlog.ReadEventLog(
#             hand,
#             flags,
#             0
#         )

#         if events:

#             for event in events:

#                 if event.RecordNumber <= last_record:
#                     continue

#                 last_record = event.RecordNumber

#                 event_id = event.EventID & 0xFFFF

#                 if event_id not in EVENTS:
#                     continue

#                 print("\n" + "=" * 70)
#                 print("SECURITY EVENT")
#                 print("=" * 70)
#                 print(f"Event ID : {event_id}")
#                 print(f"Action   : {EVENTS[event_id]}")
#                 print(f"Time     : {event.TimeGenerated}")

#                 details = ""

#                 if event.StringInserts:

#                     details = " | ".join(event.StringInserts)

#                     print("\nDetails:")
#                     print(details)

#                 insert_event(
#                     source="Security Log",
#                     event_id=str(event_id),
#                     action=EVENTS[event_id],
#                     application="Windows",
#                     details=details
#                 )

#         time.sleep(1)


import time
import subprocess
import json

from database.database import insert_event


EVENTS = {
    4688: "Process Created",
    4689: "Process Ended",
    4624: "Successful Login",
    4625: "Failed Login",
    4634: "User Logoff",
    4672: "Privileged Login",
    4648: "Explicit Credential Login",
    4768: "Kerberos TGT",
    4769: "Kerberos Service Ticket",
    4776: "Credential Validation"
}


def get_latest_events():

    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        """
        Get-WinEvent -LogName Security -MaxEvents 20 |
        Select-Object TimeCreated, Id, RecordId, Message |
        ConvertTo-Json -Compress
        """
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0 or not result.stdout.strip():
        return []

    data = json.loads(result.stdout)

    if isinstance(data, dict):
        data = [data]

    return data


def security_monitor():

    print("[Security Monitor] Started...\n")

    # Establish starting point
    initial_events = get_latest_events()

    if initial_events:
        last_record = max(
            int(event["RecordId"])
            for event in initial_events
        )
    else:
        last_record = 0

    print(f"[Security Monitor] Starting after Record: {last_record}")

    while True:

        events = get_latest_events()

        for event in reversed(events):

            record_id = int(event["RecordId"])

            if record_id <= last_record:
                continue

            last_record = record_id

            event_id = int(event["Id"])

            if event_id not in EVENTS:
                continue

            details = event.get("Message", "")

            print("\n" + "=" * 70)
            print("SECURITY EVENT")
            print("=" * 70)
            print(f"Event ID : {event_id}")
            print(f"Action   : {EVENTS[event_id]}")
            print(f"Time     : {event['TimeCreated']}")
            print(f"Record   : {record_id}")

            insert_event(
                source="Security Log",
                event_id=str(event_id),
                action=EVENTS[event_id],
                application="Windows",
                details=details
            )

        time.sleep(1)


if __name__ == "__main__":
    security_monitor()