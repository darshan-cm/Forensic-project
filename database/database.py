import sqlite3
from pathlib import Path
from datetime import datetime

DB_PATH = Path(__file__).parent / "forensic.db"


def initialize_database():
    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        timestamp TEXT,

        source TEXT,

        event_id TEXT,

        action TEXT,

        application TEXT,

        details TEXT

    )
    """)

    conn.commit()
    conn.close()


def insert_event(source, event_id, action, application, details):

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute("""

    INSERT INTO events
    (timestamp,source,event_id,action,application,details)

    VALUES(?,?,?,?,?,?)

    """,(datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
         source,
         event_id,
         action,
         application,
         details))

    conn.commit()
    conn.close()
    
def get_all_events():

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            timestamp,
            source,
            event_id,
            action,
            application,
            details
        FROM events
        ORDER BY id DESC
        LIMIT 500
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows