import sqlite3
from datetime import datetime, timedelta

DB_PATH = "database/forensic.db"

THRESHOLD = 5
WINDOW_MINUTES = 1


def detect_repeated_processes():

    conn = sqlite3.connect(DB_PATH)

    rows = conn.execute("""
        SELECT timestamp, application
        FROM events
        WHERE source = 'Process Monitor'
          AND action = 'Application Opened'
        ORDER BY timestamp, id
    """).fetchall()

    conn.close()

    suspicious = []
    i = 0

    while i < len(rows):

        start_time = datetime.strptime(
            rows[i][0],
            "%Y-%m-%d %H:%M:%S"
        )

        application = rows[i][1]

        count = 1
        j = i + 1

        while j < len(rows):

            event_time = datetime.strptime(
                rows[j][0],
                "%Y-%m-%d %H:%M:%S"
            )

            if event_time - start_time > timedelta(minutes=WINDOW_MINUTES):
                break

            if rows[j][1] == application:
                count += 1

            j += 1

        if count >= THRESHOLD:
            suspicious.append({
                "application": application,
                "count": count,
                "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S")
            })

            # Skip this burst so we don't report overlapping alerts
            i = j
        else:
            i += 1

    return suspicious


if __name__ == "__main__":

    results = detect_repeated_processes()

    print("\n=== PROCESS DETECTION ===\n")

    if not results:
        print("No suspicious repeated process activity detected.")

    else:
        for result in results:
            print(
                f"[SUSPICIOUS] "
                f"{result['application']} | "
                f"Launches: {result['count']} | "
                f"Start: {result['start_time']}"
            )