from threading import Thread
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

from monitors.security_monitor import security_monitor
from database.database import initialize_database
from monitors.process_monitor import process_monitor
from monitors.file_monitor import file_monitor
from monitors.active_window import active_window_monitor
from event_engine.worker import event_worker
from monitors.file_transfer_monitor import file_transfer_monitor
from monitors.usb_monitor import usb_monitor
from gui.app import start_gui


print("=" * 70)
print("        FORENSICGUARD - REAL TIME MONITOR")
print("=" * 70)

initialize_database()


# ============================================================
# START EVENT ENGINE WORKER
# ============================================================

Thread(
    target=event_worker,
    daemon=True
).start()


# ============================================================
# START PROCESS MONITOR
# ============================================================

Thread(
    target=process_monitor,
    daemon=True
).start()


# ============================================================
# START ACTIVE WINDOW MONITOR
# ============================================================

Thread(
    target=active_window_monitor,
    daemon=True
).start()


# ============================================================
# START SECURITY MONITOR
# ============================================================

Thread(
    target=security_monitor,
    daemon=True
).start()


# ============================================================
# START FILE MONITOR
# ============================================================

Thread(
    target=file_monitor,
    daemon=True
).start()


# ============================================================
# START FILE TRANSFER MONITOR
# ============================================================

Thread(
    target=file_transfer_monitor,
    daemon=True
).start()


# ============================================================
# START USB MONITOR
# ============================================================

Thread(
    target=usb_monitor,
    daemon=True
).start()


print("\nAll Monitors Started Successfully...\n")

start_gui()

# ============================================================
# KEEP FORENSICGUARD RUNNING
# ============================================================

try:

    while True:
        time.sleep(1)

except KeyboardInterrupt:

    print("\nStopping ForensicGuard...")