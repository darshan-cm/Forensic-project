import psutil
import time
from utils.logger import log_event


def process_monitor():
    print("[Process Monitor] Started...\n")

    previous_processes = {}

    # Initial snapshot
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            previous_processes[proc.info['pid']] = proc.info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    while True:

        current_processes = {}

        for proc in psutil.process_iter(['pid', 'name', 'exe']):

            try:
                current_processes[proc.info['pid']] = proc.info

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # -------------------------------
        # Detect newly opened applications
        # -------------------------------
        new_pids = set(current_processes) - set(previous_processes)

        for pid in new_pids:

            info = current_processes[pid]

            app = info.get("name", "Unknown")
            path = info.get("exe", "Unknown")

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

        # -------------------------------
        # Detect closed applications
        # -------------------------------
        closed_pids = set(previous_processes) - set(current_processes)

        for pid in closed_pids:

            info = previous_processes[pid]

            app = info.get("name", "Unknown")

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