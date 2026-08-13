import sqlite3
from datetime import datetime

DB_PATH = "database/forensic.db"


def get_features():

    conn = sqlite3.connect(DB_PATH)

    rows = conn.execute("""
        SELECT timestamp, event_id, action
        FROM events
        ORDER BY id
    """).fetchall()

    conn.close()

    features = {
        "USB_Event_Count": 0,
        "Email_Count": 0,
        "HTTP_Count": 0,
        "Logon_Event_Count": 0,
        "Login_Hour": 0,
        "Session_Duration_Min": 0,
        "After_Office_Hours": 0,
        "Successful_Login_Count": 0,
        "Failed_Login_Count": 0,
        "Process_Creation_Count": 0,
        "Privileged_Login_Count": 0,
        "Logoff_Count": 0,
        "Credential_Login_Count": 0,
        "Kerberos_TGT_Count": 0,
        "Kerberos_Service_Count": 0,
        "Credential_Validation_Count": 0
    }

    login_time = None

    for timestamp, event_id, action in rows:

        event_id = str(event_id)

        try:
            event_time = datetime.strptime(
                timestamp,
                "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            continue

        # Login
        if event_id == "4624":
            features["Successful_Login_Count"] += 1
            features["Logon_Event_Count"] += 1

            if login_time is None:
                login_time = event_time
                features["Login_Hour"] = event_time.hour

                if event_time.hour < 9 or event_time.hour >= 18:
                    features["After_Office_Hours"] = 1

        # Failed login
        elif event_id == "4625":
            features["Failed_Login_Count"] += 1
            features["Logon_Event_Count"] += 1

        # Process creation
        elif event_id == "4688":
            features["Process_Creation_Count"] += 1

        # Logoff
        elif event_id == "4634":
            features["Logoff_Count"] += 1

            if login_time is not None:
                duration = event_time - login_time
                features["Session_Duration_Min"] = int(
                    duration.total_seconds() / 60
                )

                login_time = None

        # Privileged logon
        elif event_id == "4672":
            features["Privileged_Login_Count"] += 1

        # Explicit credential use
        elif event_id == "4648":
            features["Credential_Login_Count"] += 1

        # Kerberos TGT
        elif event_id == "4768":
            features["Kerberos_TGT_Count"] += 1

        # Kerberos service ticket
        elif event_id == "4769":
            features["Kerberos_Service_Count"] += 1

        # Credential validation
        elif event_id == "4776":
            features["Credential_Validation_Count"] += 1

        # USB / removable storage
        elif event_id in ("4663", "4656"):
            # Kept as a placeholder until we distinguish
            # removable-storage activity from normal file access.
            pass

    return features


if __name__ == "__main__":

    result = get_features()

    print("\n=== FORENSICGUARD FEATURES ===\n")

    for name, value in result.items():
        print(f"{name}: {value}")