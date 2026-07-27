from database.database import initialize_database
from monitors.file_monitor import file_monitor

initialize_database()

file_monitor()