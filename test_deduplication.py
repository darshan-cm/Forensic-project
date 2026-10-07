#!/usr/bin/env python3
"""
Test deduplication mechanism to ensure events aren't double-assessed.
"""

import time
import sqlite3
import threading

print("="*80)
print("DEDUPLICATION TEST")
print("="*80)

from detection.event_risk_handler import assess_event, reset_deduplication
from database.database import initialize_database
from database.riskalert_db import initialize_riskalert_db
from utils.logger import log_event
from event_engine.worker import event_worker

# Initialize
initialize_database()
initialize_riskalert_db()
reset_deduplication()

# Start worker
print("\nStarting event worker...")
worker_thread = threading.Thread(target=event_worker, daemon=True)
worker_thread.start()
time.sleep(0.5)

print("\n[TEST] Simulating rapid file transfer events...")

# Clear old risk records
conn = sqlite3.connect('database/riskalert.db')
conn.execute("DELETE FROM risk_assessments")
conn.execute("DELETE FROM risk_evidence")
conn.commit()
conn.close()

print("\nLogging 3 FILE_COPY events rapidly (should trigger 1 assessment)...")
for i in range(3):
    log_event(
        source="File Transfer Monitor",
        event_id="FILE_COPY",
        action="Files Copied",
        application="Windows Explorer",
        details=f"FileCount={i+1} | TotalSize={i+1}000000 bytes"
    )
    print(f"  Event {i+1} logged")
    time.sleep(0.1)

# Let events process
print("\nWaiting for processing...")
time.sleep(2)

# Check how many assessments were created
conn = sqlite3.connect('database/riskalert.db')
cursor = conn.cursor()
cursor.execute("SELECT COUNT(*) FROM risk_assessments WHERE activity_type='FILE_COPY'")
count = cursor.fetchone()[0]
conn.close()

if count == 1:
    print(f"\n✓ DEDUPLICATION WORKING: {count} assessment created for 3 rapid events")
elif count == 3:
    print(f"\n✗ DEDUPLICATION FAILED: {count} assessments created (should be 1)")
else:
    print(f"\n? UNEXPECTED: {count} assessments (expected 1 or 3)")

# Test that waiting allows new assessment
print("\nWaiting 2.5 seconds...")
time.sleep(2.5)

print("\nLogging another FILE_COPY event (should trigger assessment)...")
log_event(
    source="File Transfer Monitor",
    event_id="FILE_COPY",
    action="Files Copied",
    application="Windows Explorer",
    details="FileCount=1 | TotalSize=5000000 bytes"
)
time.sleep(2)

# Check again
conn = sqlite3.connect('database/riskalert.db')
cursor = conn.cursor()
cursor.execute("SELECT COUNT(*) FROM risk_assessments WHERE activity_type='FILE_COPY'")
new_count = cursor.fetchone()[0]
conn.close()

if new_count > count:
    print(f"✓ NEW ASSESSMENT TRIGGERED: Now {new_count} assessments (was {count})")
else:
    print(f"✗ NO NEW ASSESSMENT: Still {new_count} assessments")

print("\n" + "="*80)
print("TEST COMPLETE")
print("="*80)
