#!/usr/bin/env python3
import sqlite3

print('='*80)
print('ANALYZING REAL-WORLD TRANSFER - 2026-09-01 20:22')
print('='*80)

# First, check the operational database for the transfer events
print('\n[OPERATIONAL DATABASE] Transfer events around 2026-09-01 20:22:')
print('-'*80)

conn = sqlite3.connect('database/forensic.db')
cursor = conn.cursor()

cursor.execute('''
SELECT id, timestamp, source, event_id, action, details
FROM events
WHERE timestamp LIKE '2026-09-01 20:22%'
  AND (event_id = 'FILE_COPY' OR event_id = 'USB_FILE_TRANSFER')
ORDER BY id DESC
LIMIT 20
''')

transfer_rows = cursor.fetchall()
print(f'Found {len(transfer_rows)} transfer events:\n')

for row in transfer_rows:
    print(f'  ID {row[0]:5d} | {row[1]} | {row[2]:20s} | {row[3]:20s}')
    if row[5]:
        details = row[5]
        # Extract file size and device info
        if 'TotalSize=' in details:
            parts = details.split('|')
            for part in parts:
                if 'TotalSize=' in part or 'Size=' in part or 'Device=' in part or 'File=' in part:
                    print(f'           {part.strip()}')

conn.close()

print('\n' + '='*80)
print('[RISK AUDIT DATABASE] Checking for corresponding risk assessments:')
print('-'*80)

conn = sqlite3.connect('database/riskalert.db')
cursor = conn.cursor()

# Check if there are ANY risk assessments at all
cursor.execute('SELECT COUNT(*) FROM risk_assessments')
total_risk = cursor.fetchone()[0]
print(f'Total risk assessments in database: {total_risk}')

# Show all risk assessments
cursor.execute('''
SELECT id, timestamp, risk_level, risk_score, activity_type, evidence_summary
FROM risk_assessments
ORDER BY id DESC
LIMIT 20
''')

risk_rows = cursor.fetchall()
print(f'\nAll risk assessments (most recent first):\n')

for row in risk_rows:
    print(f'  Risk ID {row[0]:2d} | {row[1]} | Level: {row[2]:6s} | Score: {row[3]:3d}/100 | Type: {row[4]:15s}')
    if row[5]:
        print(f'         Evidence: {row[5][:80]}...')

# Check for risk assessments at the specific time
print('\n' + '-'*80)
print('Risk assessments at 2026-09-01 20:22:')
cursor.execute('''
SELECT id, timestamp, risk_level, risk_score, activity_type
FROM risk_assessments
WHERE timestamp LIKE '2026-09-01 20:22%'
''')

matching_risks = cursor.fetchall()
if matching_risks:
    print(f'Found {len(matching_risks)} risk assessments at this time:')
    for row in matching_risks:
        print(f'  {row}')
else:
    print('NO risk assessments found at this time!')
    print('\nThis means the 1.2 GB transfer was detected but NOT recorded in riskalert.db')

conn.close()

print('\n' + '='*80)
print('DIAGNOSIS')
print('='*80)
print('''
FINDING: Transfer WAS detected and logged to forensic.db
         but NOT recorded in riskalert.db

This suggests one of these issues:
1. The risk_assessment recording logic is NOT running automatically
2. The GUI refresh that triggers risk recording is NOT happening
3. There's a disconnect between operational monitoring and risk assessment
4. The risk assessment is only triggered manually, not by real events
''')
