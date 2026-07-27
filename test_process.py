from database.database import initialize_database
from monitors.process_monitor import process_monitor

initialize_database()

process_monitor()