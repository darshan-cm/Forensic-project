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

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usb_transfers(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        timestamp TEXT,

        usb_device TEXT,

        source_path TEXT,

        destination_path TEXT,

        file_name TEXT,

        extension TEXT,

        file_size INTEGER,

        status TEXT

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

    
def insert_usb_transfer(
    usb_device,
    source_path,
    destination_path,
    file_name,
    extension,
    file_size,
    status
):

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO usb_transfers
    (
        timestamp,
        usb_device,
        source_path,
        destination_path,
        file_name,
        extension,
        file_size,
        status
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        usb_device,
        source_path,
        destination_path,
        file_name,
        extension,
        file_size,
        status
    ))

    conn.commit()
    conn.close()