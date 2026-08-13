from threading import Thread
import time

#from monitors.security_monitor import security_monitor
from database.database import initialize_database
from monitors.process_monitor import process_monitor
from monitors.file_monitor import file_monitor
from monitors.active_window import active_window_monitor
from event_engine.worker import event_worker
from monitors.file_transfer_monitor import file_transfer_monitor

print("=" * 70)
print("        FORENSICGUARD - REAL TIME MONITOR")
print("=" * 70)

initialize_database()

# Start Event Worker
# Thread(
#     target=event_worker,
#     daemon=True
# ).start()

# Start Process Monitor
Thread(
    target=process_monitor,
    daemon=True
).start()


Thread(
    target=active_window_monitor,
    daemon=True
).start()

# Thread(
#     target=security_monitor,
#     daemon=True
# ).start()
# Start File Monitor
Thread(
    target=file_monitor,
    daemon=True
).start()

Thread(
    target=file_transfer_monitor,
    daemon=True
).start()

print("\nAll Monitors Started Successfully...\n")

try:
    while True:
        time.sleep(1)

except KeyboardInterrupt:
    print("\nStopping ForensicGuard...")