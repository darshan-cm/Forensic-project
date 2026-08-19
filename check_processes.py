import sqlite3

conn = sqlite3.connect("database/forensic.db")

rows = conn.execute("""
SELECT timestamp, event_id, action, application
FROM events
WHERE timestamp >= datetime('now', '-5 minutes')
AND event_id = '4688'
ORDER BY id DESC
""").fetchall()

for row in rows:
    print(row)

conn.close()