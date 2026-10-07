#!/usr/bin/env python3
"""
Comprehensive diagnostic for SD card transfer detection and risk assessment pipeline.
"""
import sqlite3
from datetime import datetime, timedelta

print("\n" + "="*90)
print("DIAGNOSTIC: Real-World SD Card Transfer Detection")
print("="*90)

# ============================================================================
# 1. OPERATIONAL DATABASE CHECK
# ============================================================================
print("\n\n[1] OPERATIONAL DATABASE - Recent Events")
print("-" * 90)

conn = sqlite3.connect('database/database.db')
cursor = conn.cursor()

# Get the last 100 events, sorted by ID DESC
rows = cursor.execute('''
    SELECT id, timestamp, source, event_id, action, application, details
    FROM events
    ORDER BY id DESC
    LIMIT 100
''').fetchall()

print(f"Total events in database: {len(rows)}\n")

# Filter for file transfer related events
transfer_events = [r for r in rows if any(x in str(r).upper() for x in ['FILE', 'USB', 'MTP', 'TRANSFER', 'COPY', 'SD', 'CARD', 'CLIPBOARD'])]

if transfer_events:
    print(f"Found {len(transfer_events)} transfer-related events in last 100:\n")
    for row in transfer_events[:30]:  # Show top 30
        print(f"  ID: {row[0]:5d} | Time: {row[1]} | Source: {row[2]:20s} | Event: {row[3]:20s}")
        print(f"         Action: {row[4]:30s} | App: {row[5]:15s}")
        print(f"         Details: {row[6]}")
        print()
else:
    print("NO transfer-related events found in last 100 events")
    print("\nAll recent events:")
    for row in rows[:20]:
        print(f"  ID: {row[0]:5d} | Time: {row[1]} | Source: {row[2]:20s} | Event: {row[3]:20s} | Action: {row[4]}")

conn.close()

# ============================================================================
# 2. RISKALERT DATABASE CHECK
# ============================================================================
print("\n\n[2] RISK ALERT DATABASE - Recent Assessments")
print("-" * 90)

try:
    conn = sqlite3.connect('database/riskalert.db')
    cursor = conn.cursor()
    
    # Get the last 20 risk assessments
    risk_rows = cursor.execute('''
        SELECT id, timestamp, risk_level, risk_score, activity_type, trigger_event_id, 
               trigger_event_source, trigger_application, trigger_details, 
               evidence_summary, notification_triggered, notification_status, alert_message
        FROM risk_assessments
        ORDER BY id DESC
        LIMIT 20
    ''').fetchall()
    
    print(f"Total risk assessments: {len(risk_rows)}\n")
    
    for row in risk_rows[:10]:
        print(f"  Risk ID: {row[0]:5d}")
        print(f"    Timestamp: {row[1]} | Level: {row[2]} | Score: {row[3]}/100")
        print(f"    Activity: {row[4]} | Trigger: {row[5]}")
        print(f"    Source: {row[6]} | App: {row[7]}")
        print(f"    Details: {row[8]}")
        print(f"    Evidence: {row[9]}")
        print(f"    Notification: Triggered={row[10]} | Status={row[11]}")
        print(f"    Message: {row[12]}")
        print()
    
    # Get recent evidence rows
    evidence_rows = cursor.execute('''
        SELECT id, risk_id, evidence_text, event_id, event_source, application,
               file_path, source_path, destination_path, usb_device, process_name, process_id
        FROM risk_evidence
        ORDER BY id DESC
        LIMIT 20
    ''').fetchall()
    
    print(f"\nTotal evidence rows: {len(evidence_rows)}\n")
    
    for row in evidence_rows[:15]:
        print(f"  Evidence ID: {row[0]:5d} | Risk ID: {row[1]:5d}")
        print(f"    Text: {row[2]}")
        print(f"    Event: {row[3]} | Source: {row[4]} | App: {row[5]}")
        print(f"    File: {row[6]} | Source: {row[7]}")
        print(f"    Dest: {row[8]} | USB: {row[9]}")
        print(f"    Process: {row[10]} ({row[11]})")
        print()
    
    conn.close()
except Exception as e:
    print(f"ERROR accessing riskalert.db: {e}")

# ============================================================================
# 3. FILE TRANSFER MONITOR ANALYSIS
# ============================================================================
print("\n\n[3] FILE TRANSFER MONITOR - Implementation Analysis")
print("-" * 90)

print("Checking file_transfer_monitor.py for detection methods...\n")

try:
    with open('monitors/file_transfer_monitor.py', 'r') as f:
        content = f.read()
        
    # Check for detection methods
    detection_methods = [
        'record_file_copy',
        'clipboard_monitor',
        'mtp_paste_monitor',
        'USBMonitor',
        'WinEventHook',
        'win32clipboard',
        'GetClipboardData'
    ]
    
    print("Detection methods found:")
    for method in detection_methods:
        if method in content:
            print(f"  ✓ {method}")
        else:
            print(f"  ✗ {method}")
    
    # Look for SD card detection
    if 'SD' in content or 'card' in content.lower():
        print("\n  Note: SD card specific detection might be present")
    else:
        print("\n  Note: No explicit SD card detection found (may be detected as generic USB)")
        
except Exception as e:
    print(f"ERROR reading file_transfer_monitor.py: {e}")

# ============================================================================
# 4. RISK ENGINE ANALYSIS
# ============================================================================
print("\n\n[4] RISK ENGINE - Scoring Rules")
print("-" * 90)

print("Checking risk_engine.py for scoring logic...\n")

try:
    with open('detection/risk_engine.py', 'r') as f:
        content = f.read()
    
    # Extract key scoring variables
    if 'files_copied' in content:
        print("  ✓ Files copied counted in scoring")
    if 'total_copy_size' in content:
        print("  ✓ Total copy size affects scoring")
    if 'usb_connections' in content:
        print("  ✓ USB connections affect scoring")
    if 'failed_logins' in content or 'security_events' in content:
        print("  ✓ Security events affect scoring")
    
    # Look for thresholds
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if 'HIGH' in line and ('=' in line or '>' in line or '<' in line):
            print(f"\n  Threshold line: {line.strip()}")
            if i+1 < len(lines):
                print(f"  Next line:      {lines[i+1].strip()}")
        
except Exception as e:
    print(f"ERROR reading risk_engine.py: {e}")

# ============================================================================
# 5. ALERT MANAGER ANALYSIS
# ============================================================================
print("\n\n[5] ALERT MANAGER - Notification Logic")
print("-" * 90)

print("Checking alert_manager.py for notification handling...\n")

try:
    with open('alerts/alert_manager.py', 'r') as f:
        content = f.read()
    
    # Check for notification methods
    if '_show_windows_notification' in content:
        print("  ✓ Windows notification method present")
    if 'Toast' in content or 'toast' in content:
        print("  ✓ Toast notification support")
    if 'state_transitions' in content:
        print("  ✓ State-based notification logic")
    if 'anti_spam' in content or 'suppress' in content:
        print("  ✓ Anti-spam/suppression logic")
        
except Exception as e:
    print(f"ERROR reading alert_manager.py: {e}")

print("\n" + "="*90)
print("DIAGNOSTIC COMPLETE")
print("="*90 + "\n")
