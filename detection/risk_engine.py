# detection/risk_engine.py

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

DB_PATH = Path("database/forensic.db")

# Only recent activity is considered.
WINDOW_MINUTES = 10

# Time after a FILE_COPY event in which an MTP/phone
# Explorer window can be considered related to that transfer.
MTP_CORRELATION_SECONDS = 120

MAX_SCORE = 100


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score):

    if score >= 70:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    return "LOW"


# ============================================================
# SIZE FORMATTER
# ============================================================

def format_size(size):

    if size is None:
        return "0 B"

    size = float(size)

    if size < 1024:
        return f"{int(size)} B"

    if size < 1024 * 1024:
        return f"{size / 1024:.2f} KB"

    if size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MB"

    return f"{size / (1024 * 1024 * 1024):.2f} GB"


# ============================================================
# TIMESTAMP PARSER
# ============================================================

def parse_timestamp(timestamp):

    try:
        return datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S"
        )

    except (ValueError, TypeError):

        return None


# ============================================================
# GET RECENT EVENTS
# ============================================================

def get_recent_events():

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cutoff = datetime.now() - timedelta(
        minutes=WINDOW_MINUTES
    )

    rows = cursor.execute(
        """
        SELECT
            id,
            timestamp,
            source,
            event_id,
            action,
            application,
            details
        FROM events
        WHERE timestamp >= ?
        ORDER BY id ASC
        """,
        (
            cutoff.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
        )
    ).fetchall()

    conn.close()

    return rows


# ============================================================
# MTP / PHONE WINDOW DETECTION
#
# IMPORTANT:
# This does NOT claim that a paste was definitely successful.
#
# Windows MTP devices do not behave like normal filesystem
# drives, so watchdog cannot reliably generate FILE_CREATE
# events for the phone.
#
# We therefore detect:
#
# USB connected
#       +
# FILE_COPY
#       +
# Phone / Internal Storage / MTP Explorer window
#
# and report:
#
# MTP DESTINATION SUSPECTED
#
# rather than falsely claiming:
#
# FILE PASTED
# ============================================================

def is_mtp_window(application):

    if not application:
        return False

    text = str(application).lower()

    mtp_keywords = [

        # Generic phone/storage terms
        "internal shared storage",
        "internal storage",
        "phone storage",
        "phone",
        "mobile device",
        "portable device",
        "mtp",

        # Windows Explorer indicators
        "file explorer",

        # Common Android storage names
        "dcim",
        "pictures",
        "documents",
        "download",
        "project"
    ]

    return any(
        keyword in text
        for keyword in mtp_keywords
    )


# ============================================================
# ANALYZE FORENSIC ACTIVITY
# ============================================================

def assess_risk():

    events = get_recent_events()


    # ========================================================
    # COUNTERS
    # ========================================================

    usb_connections = 0
    usb_removals = 0

    files_copied = 0
    total_copy_size = 0

    security_events = 0

    file_deletions = 0
    file_creations = 0
    file_modifications = 0

    application_events = 0


    # ========================================================
    # FLAGS
    # ========================================================

    bulk_transfer = False
    large_transfer = False

    deletion_activity = False
    security_anomaly = False

    mtp_window_detected = False
    mtp_transfer_suspected = False


    # ========================================================
    # EVENT STORAGE
    # ========================================================

    copy_events = []
    mtp_windows = []


    # ========================================================
    # EVIDENCE
    # ========================================================

    evidence = []


    # ========================================================
    # PROCESS EVENTS
    # ========================================================

    for row in events:

        (
            event_id_db,
            timestamp,
            source,
            event_id,
            action,
            application,
            details
        ) = row


        event_id = str(
            event_id or ""
        ).upper()

        source_text = str(
            source or ""
        ).lower()

        application_text = str(
            application or ""
        )

        details_text = str(
            details or ""
        )


        event_time = parse_timestamp(
            timestamp
        )


        # ====================================================
        # USB CONNECTED
        # ====================================================

        if event_id == "USB_CONNECTED":

            usb_connections += 1


        # ====================================================
        # USB REMOVED
        # ====================================================

        elif event_id == "USB_REMOVED":

            usb_removals += 1


        # ====================================================
        # FILE COPY
        # ====================================================

        elif event_id == "FILE_COPY":

            count = 0
            size = 0


            # ------------------------------------------------
            # File count
            # ------------------------------------------------

            if "FileCount=" in details_text:

                try:

                    value = details_text.split(
                        "FileCount=",
                        1
                    )[1]

                    value = value.split(
                        "|",
                        1
                    )[0]

                    count = int(
                        value.strip()
                    )

                except Exception:

                    count = 0


            # ------------------------------------------------
            # Total size
            # ------------------------------------------------

            if "TotalSize=" in details_text:

                try:

                    value = details_text.split(
                        "TotalSize=",
                        1
                    )[1]

                    value = value.split(
                        "bytes",
                        1
                    )[0]

                    size = int(
                        value.strip()
                    )

                except Exception:

                    size = 0


            files_copied += count

            total_copy_size += size


            if event_time:

                copy_events.append(
                    event_time
                )


        # ====================================================
        # FILE DELETE
        # ====================================================

        elif event_id == "FILE_DELETE":

            file_deletions += 1

            deletion_activity = True


        # ====================================================
        # FILE CREATE
        # ====================================================

        elif event_id == "FILE_CREATE":

            file_creations += 1


        # ====================================================
        # FILE MODIFY
        # ====================================================

        elif event_id == "FILE_MODIFY":

            file_modifications += 1


        # ====================================================
        # PROCESS / APPLICATION
        # ====================================================

        elif event_id in (
            "4688",
            "4689"
        ):

            application_events += 1


        # ====================================================
        # ACTIVE WINDOW / MTP WINDOW
        # ====================================================

        if event_id == "WINDOW_CHANGE":

            if is_mtp_window(
                application_text
            ):

                mtp_window_detected = True

                if event_time:

                    mtp_windows.append(
                        event_time
                    )


        # ====================================================
        # SECURITY EVENTS
        # ====================================================

        if (
            "security" in source_text
            or event_id in (
                "4625",
                "4776"
            )
        ):

            security_events += 1

            security_anomaly = True


    # ========================================================
    # DERIVED INDICATORS
    # ========================================================

    if files_copied >= 3:

        bulk_transfer = True


    if total_copy_size >= (
        100 * 1024 * 1024
    ):

        large_transfer = True


    # ========================================================
    # MTP TRANSFER CORRELATION
    #
    # We only call it "suspected".
    #
    # We NEVER claim the paste succeeded because Windows
    # does not expose MTP copy/paste as a normal filesystem
    # event.
    # ========================================================

    if (
        usb_connections > 0
        and files_copied > 0
        and mtp_windows
        and copy_events
    ):

        for copy_time in copy_events:

            for window_time in mtp_windows:

                difference = (
                    window_time - copy_time
                ).total_seconds()

                if (
                    0 <= difference
                    <= MTP_CORRELATION_SECONDS
                ):

                    mtp_transfer_suspected = True

                    break

            if mtp_transfer_suspected:

                break


    # ========================================================
    # SCORE
    # ========================================================

    score = 0


    # ========================================================
    # USB ACTIVITY
    # ========================================================

    if usb_connections > 0:

        score += 5

        evidence.append(
            "External USB device activity detected."
        )


    # ========================================================
    # FILE COPY ACTIVITY
    # ========================================================

    if files_copied > 0:

        if files_copied <= 2:

            score += 5

            evidence.append(
                f"{files_copied} file(s) copied."
            )

        elif files_copied < 10:

            score += 10

            evidence.append(
                f"Bulk file-copy activity detected "
                f"({files_copied} files)."
            )

        else:

            score += 20

            evidence.append(
                f"High-volume file-copy activity detected "
                f"({files_copied} files)."
            )


    # ========================================================
    # TRANSFER SIZE
    # ========================================================

    if total_copy_size >= (
        100 * 1024 * 1024
    ):

        score += 20

        evidence.append(
            "Large data transfer volume detected "
            f"({format_size(total_copy_size)})."
        )

    elif total_copy_size >= (
        10 * 1024 * 1024
    ):

        score += 10

        evidence.append(
            "Moderate data transfer volume detected "
            f"({format_size(total_copy_size)})."
        )

    elif total_copy_size > 0:

        evidence.append(
            f"Transfer volume: "
            f"{format_size(total_copy_size)}."
        )


    # ========================================================
    # USB + FILE COPY
    # ========================================================

    if (
        usb_connections > 0
        and files_copied > 0
    ):

        score += 10

        evidence.append(
            "USB activity correlated with "
            "file-copy behavior."
        )


    # ========================================================
    # USB + BULK TRANSFER
    # ========================================================

    if (
        usb_connections > 0
        and bulk_transfer
    ):

        score += 10

        evidence.append(
            "Bulk transfer occurred while "
            "an external USB device was active."
        )


    # ========================================================
    # MTP / PHONE TRANSFER
    #
    # IMPORTANT:
    # This adds only a SMALL amount of risk because a phone
    # transfer by itself is not malicious.
    # ========================================================

    if mtp_transfer_suspected:

        score += 5

        evidence.append(
            "MTP/phone destination activity correlated "
            "with the file-copy event."
        )

        evidence.append(
            "Destination is suspected but cannot be "
            "verified through the Windows MTP interface."
        )


    elif (
        mtp_window_detected
        and usb_connections > 0
    ):

        evidence.append(
            "Phone/MTP Explorer activity detected."
        )


    # ========================================================
    # SECURITY ANOMALY + TRANSFER
    # ========================================================

    if (
        security_anomaly
        and files_copied > 0
    ):

        score += 20

        evidence.append(
            "Security anomaly correlated with "
            "file-transfer activity."
        )

    elif security_anomaly:

        score += 10

        evidence.append(
            "Security-related anomaly detected."
        )


    # ========================================================
    # DELETION + TRANSFER
    # ========================================================

    if (
        deletion_activity
        and files_copied > 0
    ):

        score += 10

        evidence.append(
            "File deletion occurred during "
            "file-transfer activity."
        )


    # ========================================================
    # LARGE TRANSFER + USB
    # ========================================================

    if (
        large_transfer
        and usb_connections > 0
    ):

        score += 10

        evidence.append(
            "Large transfer correlated with "
            "external USB activity."
        )


    # ========================================================
    # LIMIT SCORE
    # ========================================================

    score = min(
        score,
        MAX_SCORE
    )


    # ========================================================
    # RISK LEVEL
    # ========================================================

    risk = get_risk_level(
        score
    )


    # ========================================================
    # TRANSFER STATUS
    # ========================================================

    if files_copied == 0:

        transfer_status = (
            "NO FILE TRANSFER DETECTED"
        )

    elif mtp_transfer_suspected:

        transfer_status = (
            "MTP DESTINATION SUSPECTED / "
            "DESTINATION UNVERIFIED"
        )

    elif usb_connections > 0:

        transfer_status = (
            "USB TRANSFER ACTIVITY DETECTED"
        )

    else:

        transfer_status = (
            "COPY DETECTED / "
            "DESTINATION UNVERIFIED"
        )


    # ========================================================
    # NO EVIDENCE
    # ========================================================

    if not evidence:

        evidence.append(
            "No significant forensic indicators."
        )


    # ========================================================
    # FINAL RESULT
    # ========================================================

    result = {

        "risk":
            risk,

        "score":
            score,

        "usb_connections":
            usb_connections,

        "usb_removals":
            usb_removals,

        "files_copied":
            files_copied,

        "total_copy_size":
            total_copy_size,

        "total_copy_size_display":
            format_size(
                total_copy_size
            ),

        "security_events":
            security_events,

        "file_deletions":
            file_deletions,

        "file_creations":
            file_creations,

        "file_modifications":
            file_modifications,

        "application_events":
            application_events,

        "mtp_window_detected":
            mtp_window_detected,

        "mtp_transfer_suspected":
            mtp_transfer_suspected,

        "transfer_status":
            transfer_status,

        "evidence":
            evidence,

        "window_minutes":
            WINDOW_MINUTES
    }


    return result


# ============================================================
# TERMINAL DISPLAY
# ============================================================

def print_assessment():

    result = assess_risk()


    print()
    print("=" * 70)

    print(
        "FORENSICGUARD - FORENSIC RISK ASSESSMENT"
    )

    print("=" * 70)


    print(
        f"\nRisk Level       : "
        f"{result['risk']}"
    )

    print(
        f"Risk Score       : "
        f"{result['score']}/100"
    )

    print(
        f"USB Connections  : "
        f"{result['usb_connections']}"
    )

    print(
        f"Files Copied     : "
        f"{result['files_copied']}"
    )

    print(
        f"Total Copy Size  : "
        f"{result['total_copy_size_display']}"
    )

    print(
        f"Security Events  : "
        f"{result['security_events']}"
    )

    print(
        f"MTP Activity     : "
        f"{'YES' if result['mtp_window_detected'] else 'NO'}"
    )

    print(
        f"MTP Transfer     : "
        f"{'SUSPECTED' if result['mtp_transfer_suspected'] else 'NOT VERIFIED'}"
    )

    print(
        f"Transfer Status  : "
        f"{result['transfer_status']}"
    )


    print(
        "\nEvidence:"
    )


    for item in result["evidence"]:

        print(
            f"  • {item}"
        )


    print(
        "=" * 70
    )


# ============================================================
# DIRECT EXECUTION
# ============================================================

if __name__ == "__main__":

    print_assessment()