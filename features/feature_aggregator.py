import sqlite3
from datetime import datetime, timedelta


DB_PATH = "database/forensic.db"
WINDOW_MINUTES = 5


# ============================================================
# PROCESSES RELEVANT TO OBJECTIVE-2 ML BEHAVIOR
# ============================================================

USER_RELEVANT_PROCESSES = {
    "notepad.exe",
    "whatsapp.exe",
    "whatsapp.root.exe",
    "code.exe",
    "code-insiders.exe",
    "explorer.exe",
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "discord.exe",
    "anydesk.exe",
}


# ============================================================
# FEATURES EXPECTED BY THE TRAINED ML MODEL
#
# IMPORTANT:
# The current forensicguard_rf.pkl was trained using
# EXACTLY these 8 features.
# ============================================================

ML_FEATURES = [
    "Successful_Login_Count",
    "Failed_Login_Count",
    "Process_Creation_Count",
    "Logoff_Count",
    "Credential_Validation_Count",
    "Total_Events",
    "Login_Hour",
    "After_Office_Hours"
]


def get_features():

    conn = sqlite3.connect(DB_PATH)

    cutoff = datetime.now() - timedelta(
        minutes=WINDOW_MINUTES
    )

    rows = conn.execute("""
        SELECT timestamp, event_id, action, application
        FROM events
        WHERE timestamp >= ?
        ORDER BY id
    """, (
        cutoff.strftime("%Y-%m-%d %H:%M:%S"),
    )).fetchall()

    conn.close()


    # ========================================================
    # ML FEATURE VECTOR
    # ========================================================

    features = {

        "Successful_Login_Count": 0,

        "Failed_Login_Count": 0,

        "Process_Creation_Count": 0,

        "Logoff_Count": 0,

        "Credential_Validation_Count": 0,

        "Total_Events": 0,

        "Login_Hour": 0,

        "After_Office_Hours": 0
    }


    login_time = None


    # ========================================================
    # PROCESS EVENTS
    # ========================================================

    for timestamp, event_id, action, application in rows:

        event_id = str(event_id).strip()

        application = str(
            application or ""
        ).strip().lower()


        try:

            event_time = datetime.strptime(
                timestamp,
                "%Y-%m-%d %H:%M:%S"
            )

        except (ValueError, TypeError):

            continue


        # ====================================================
        # SUCCESSFUL LOGIN
        # ====================================================

        if event_id == "4624":

            features[
                "Successful_Login_Count"
            ] += 1

            features[
                "Total_Events"
            ] += 1


            if login_time is None:

                login_time = event_time

                features[
                    "Login_Hour"
                ] = event_time.hour


                if (
                    event_time.hour < 9
                    or event_time.hour >= 18
                ):

                    features[
                        "After_Office_Hours"
                    ] = 1


        # ====================================================
        # FAILED LOGIN
        # ====================================================

        elif event_id == "4625":

            features[
                "Failed_Login_Count"
            ] += 1

            features[
                "Total_Events"
            ] += 1


        # ====================================================
        # PROCESS CREATION
        # ====================================================

        elif event_id == "4688":

            # Only count meaningful user applications.
            #
            # Background processes such as PowerShell,
            # Python, system services etc. are excluded.

            if application in USER_RELEVANT_PROCESSES:

                features[
                    "Process_Creation_Count"
                ] += 1

                features[
                    "Total_Events"
                ] += 1


        # ====================================================
        # LOGOFF
        # ====================================================

        elif event_id in (
            "4634",
            "4647"
        ):

            features[
                "Logoff_Count"
            ] += 1

            features[
                "Total_Events"
            ] += 1


        # ====================================================
        # CREDENTIAL VALIDATION
        # ====================================================

        elif event_id == "4776":

            features[
                "Credential_Validation_Count"
            ] += 1

            features[
                "Total_Events"
            ] += 1


        # ====================================================
        # IMPORTANT:
        #
        # 4689
        # FILE_CREATE
        # FILE_MODIFY
        # FILE_DELETE
        # FILE_RENAME
        # FILE_COPY
        # WINDOW_CHANGE
        #
        # are still stored in the forensic database and
        # monitored by Objective 1.
        #
        # BUT they are NOT added to the Objective-2
        # Total_Events count because the current ML model
        # was not trained using those features.
        # ====================================================


    return features


# ============================================================
# DISPLAY FEATURES
# ============================================================

if __name__ == "__main__":

    print(
        "\n=== FORENSICGUARD ML FEATURES ===\n"
    )

    features = get_features()

    for name in ML_FEATURES:

        print(
            f"{name}: {features[name]}"
        )

    print(
        "\nTotal ML features:",len(ML_FEATURES)
    )