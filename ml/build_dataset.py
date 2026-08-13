import sqlite3
import pandas as pd

DB_PATH = "database/forensic.db"
OUTPUT = "ml/forensicguard_dataset.csv"

WINDOW_MINUTES = "5min"


def build_dataset():

    conn = sqlite3.connect(DB_PATH)

    df = pd.read_sql_query("""
        SELECT
            timestamp,
            source,
            event_id,
            action
        FROM events
        ORDER BY timestamp
    """, conn)

    conn.close()

    if df.empty:
        print("No events found.")
        return

    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # --------------------------------------------------
    # Create 5-minute behavioral windows
    # --------------------------------------------------

    df["window"] = df["timestamp"].dt.floor(WINDOW_MINUTES)

    dataset = []

    for window, group in df.groupby("window"):

        row = {
            "Window_Start": window,

            # Windows Security
            "Successful_Login_Count":
                ((group["event_id"] == "4624")).sum(),

            "Failed_Login_Count":
                ((group["event_id"] == "4625")).sum(),

            "Process_Creation_Count":
                ((group["event_id"] == "4688")).sum(),

            "Privileged_Login_Count":
                ((group["event_id"] == "4672")).sum(),

            "Logoff_Count":
                ((group["event_id"] == "4634")).sum(),

            "Credential_Login_Count":
                ((group["event_id"] == "4648")).sum(),

            "Kerberos_TGT_Count":
                ((group["event_id"] == "4768")).sum(),

            "Kerberos_Service_Count":
                ((group["event_id"] == "4769")).sum(),

            "Credential_Validation_Count":
                ((group["event_id"] == "4776")).sum(),

            # ForensicGuard-specific activity
            "File_Created_Count":
                ((group["action"] == "File Created")).sum(),

            "File_Modified_Count":
                (
                    group["action"]
                    .isin(["File Modified", "File Modified / Saved"])
                ).sum(),

            "File_Deleted_Count":
                ((group["action"] == "File Deleted")).sum(),

            "File_Renamed_Count":
                (
                    group["action"]
                    .isin(["File Renamed", "File Renamed / Moved"])
                ).sum(),

            "Process_Closed_Count":
                ((group["action"] == "Application Closed")).sum(),

            "Active_Window_Change_Count":
                ((group["action"] == "Window Changed")).sum(),

            "Total_Events":
                len(group)
        }

        # --------------------------------------------------
        # Time-based features
        # --------------------------------------------------

        hour = window.hour

        row["Login_Hour"] = hour

        row["After_Office_Hours"] = int(
            hour < 9 or hour >= 18
        )

        # --------------------------------------------------
        # Label
        # --------------------------------------------------

        # We DO NOT invent labels here.
        row["Risk_Label"] = ""

        dataset.append(row)

    result = pd.DataFrame(dataset)

    result.to_csv(
        OUTPUT,
        index=False
    )

    print("\n=== FORENSICGUARD DATASET ===")
    print(f"Rows    : {len(result)}")
    print(f"Columns : {len(result.columns)}")
    print(f"Saved   : {OUTPUT}")

    print("\nFirst rows:")
    print(result.head())


if __name__ == "__main__":
    build_dataset()