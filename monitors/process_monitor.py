import psutil
import time

from utils.logger import log_event


# ============================================================
# USER-FACING APPLICATIONS
#
# Only these applications are considered meaningful
# application activity for ForensicGuard.
#
# Background Windows processes, services, drivers,
# Git, PostgreSQL, etc. are intentionally ignored.
# ============================================================

MONITORED_APPLICATIONS = {
    "notepad.exe",

    # Browsers
    "chrome.exe",
    "brave.exe",
    "msedge.exe",
    "firefox.exe",

    # Development
    "code.exe",
    "code-insiders.exe",

    # Communication
    "whatsapp.exe",
    "whatsapp.root.exe",
    "discord.exe",

    # Windows user applications
    "explorer.exe",

    # Microsoft Office
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",

    # Remote access
    "anydesk.exe",
}


# ============================================================
# CHECK WHETHER APPLICATION SHOULD BE MONITORED
# ============================================================

def should_monitor(process_name):

    if not process_name:
        return False

    return (
        process_name.lower()
        in MONITORED_APPLICATIONS
    )


# ============================================================
# PROCESS MONITOR
# ============================================================

def process_monitor():

    print("[Process Monitor] Started...\n")

    # --------------------------------------------------------
    # Initial process snapshot
    # --------------------------------------------------------

    previous_processes = {}

    for proc in psutil.process_iter(
        ["pid", "name", "exe"]
    ):

        try:

            previous_processes[
                proc.info["pid"]
            ] = proc.info

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied
        ):

            continue


    # ========================================================
    # MAIN MONITORING LOOP
    # ========================================================

    while True:

        current_processes = {}


        # ----------------------------------------------------
        # Get current process snapshot
        # ----------------------------------------------------

        for proc in psutil.process_iter(
            ["pid", "name", "exe"]
        ):

            try:

                current_processes[
                    proc.info["pid"]
                ] = proc.info

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied
            ):

                continue


        # ====================================================
        # APPLICATION OPENED
        # ====================================================

        new_pids = (
            set(current_processes)
            - set(previous_processes)
        )


        # Names of applications already running BEFORE
        previous_applications = {
            (
                info.get("name") or ""
            ).lower()

            for info in previous_processes.values()
            if should_monitor(
                info.get("name")
            )
        }


        # Names of applications currently running
        current_applications = {
            (
                info.get("name") or ""
            ).lower()

            for info in current_processes.values()
            if should_monitor(
                info.get("name")
            )
        }


        # ----------------------------------------------------
        # Process creation events
        #
        # We only report an application when the application
        # itself was not already running.
        #
        # This prevents Chrome/Brave from generating many
        # events because of renderer/helper processes.
        # ----------------------------------------------------

        logged_opened = set()


        for pid in new_pids:

            info = current_processes[pid]

            app = (
                info.get("name")
                or "Unknown"
            )

            app_lower = app.lower()

            path = (
                info.get("exe")
                or "Unknown"
            )


            if not should_monitor(app):
                continue


            # Already running application?
            if app_lower in previous_applications:
                continue


            # Prevent duplicate logging within this scan
            if app_lower in logged_opened:
                continue


            logged_opened.add(
                app_lower
            )


            print("=" * 70)
            print("APPLICATION OPENED")
            print(f"Application : {app}")
            print(f"PID         : {pid}")
            print(f"Path        : {path}")


            log_event(
                source="Process Monitor",
                event_id="4688",
                action="Application Opened",
                application=app,
                details=f"PID={pid} | {path}"
            )


        # ====================================================
        # APPLICATION CLOSED
        # ====================================================

        closed_pids = (
            set(previous_processes)
            - set(current_processes)
        )


        logged_closed = set()


        for pid in closed_pids:

            info = previous_processes[pid]

            app = (
                info.get("name")
                or "Unknown"
            )

            app_lower = app.lower()


            if not should_monitor(app):
                continue


            # ------------------------------------------------
            # If another PID of the same application is still
            # running, the application itself has NOT closed.
            #
            # This is important for Chrome/Brave/Edge.
            # ------------------------------------------------

            if app_lower in current_applications:
                continue


            # Prevent duplicate close events
            if app_lower in logged_closed:
                continue


            logged_closed.add(
                app_lower
            )


            print("=" * 70)
            print("APPLICATION CLOSED")
            print(f"Application : {app}")
            print(f"PID         : {pid}")


            log_event(
                source="Process Monitor",
                event_id="4689",
                action="Application Closed",
                application=app,
                details=f"PID={pid}"
            )


        # ----------------------------------------------------
        # Update snapshot
        # ----------------------------------------------------

        previous_processes = (
            current_processes
        )


        time.sleep(1)


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    try:

        process_monitor()

    except KeyboardInterrupt:

        print(
            "\n[Process Monitor] Stopped."
        )