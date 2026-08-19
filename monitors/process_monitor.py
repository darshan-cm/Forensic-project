import psutil
import time
from utils.logger import log_event


# Processes that commonly create background PID churn.
# These are ignored to reduce normal Windows noise.
IGNORED_PROCESSES = {
    "conhost.exe",
    "svchost.exe",
    "csrss.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "lsass.exe",
    "services.exe",
    "smss.exe",
    "wininit.exe",
    "winlogon.exe",
    "sihost.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "searchhost.exe",
    "searchindexer.exe",
    "searchprotocolhost.exe",
    "startmenuexperiencehost.exe",
    "shellexperiencehost.exe",
    "applicationframehost.exe",
    "textinputhost.exe",
    "ctfmon.exe",
    "dllhost.exe",
    "wmiprvse.exe",
    "wmiapsrv.exe",
    "wu dfhost.exe",
    "widgets.exe",
    "widgetservice.exe",
    "msedgewebview2.exe",
    "powershell.exe",
    "pwsh.exe",
    "python.exe",
    "pythonw.exe",
    "dataexchangehost.exe",
    "smartscreen.exe",
    "audiodg.exe",
}


def should_ignore(process_name):
    if not process_name:
        return True

    return process_name.lower() in IGNORED_PROCESSES


def process_monitor():

    print("[Process Monitor] Started...\n")

    previous_processes = {}

    # Initial snapshot
    for proc in psutil.process_iter(["pid", "name", "exe"]):

        try:
            previous_processes[proc.info["pid"]] = proc.info

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    while True:

        current_processes = {}

        for proc in psutil.process_iter(["pid", "name", "exe"]):

            try:
                current_processes[proc.info["pid"]] = proc.info

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # =====================================================
        # APPLICATION OPENED
        # =====================================================

        new_pids = set(current_processes) - set(previous_processes)

        for pid in new_pids:

            info = current_processes[pid]

            app = info.get("name", "Unknown")
            path = info.get("exe", "Unknown")

            if should_ignore(app):
                continue

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

        # =====================================================
        # APPLICATION CLOSED
        # =====================================================

        closed_pids = set(previous_processes) - set(current_processes)

        for pid in closed_pids:

            info = previous_processes[pid]

            app = info.get("name", "Unknown")

            if should_ignore(app):
                continue

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

        previous_processes = current_processes

        time.sleep(1)