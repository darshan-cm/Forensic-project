from database.database import initialize_database
from database.database import insert_event

initialize_database()

insert_event(
    source="TEST",
    event_id="0000",
    action="Database Working",
    application="Python",
    details="Everything is fine."
)

print("Database Created Successfully")