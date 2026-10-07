#!/usr/bin/env python3
import sqlite3

print('='*80)
print('SEARCHING FOR FILE TRANSFER EVENTS IN OPERATIONAL DATABASE')
print('='*80)

conn = sqlite3.connect('database/forensic.db')
cursor = conn.cursor()

# Search for any transfer-related events
keywords = ['FILE', 'COPY', 'USB', 'MTP', 'TRANSFER', 'SD', 'REMOVABLE', 'DRIVE', 'DEVICE']

print(f'\nSearching for keywords: {", ".join(keywords)}\n')

query = '''
SELECT id, timestamp, source, event_id, action, application, details
FROM events
WHERE 
    UPPER(event_id) LIKE '%FILE%' OR
    UPPER(event_id) LIKE '%USB%' OR
    UPPER(event_id) LIKE '%MTP%' OR
    UPPER(event_id) LIKE '%TRANSFER%' OR
    UPPER(event_id) LIKE '%COPY%' OR
    UPPER(source) LIKE '%FILE%' OR
    UPPER(source) LIKE '%USB%' OR
    UPPER(source) LIKE '%MTP%' OR
    UPPER(source) LIKE '%TRANSFER%'
ORDER BY id DESC
LIMIT 50
'''

cursor.execute(query)
rows = cursor.fetchall()

if rows:
    print(f'Found {len(rows)} file transfer related events:\n')
    for row in rows:
        print(f'  ID {row[0]:5d} | {row[1]} | {row[2]:25s} | {row[3]:20s}')
        print(f'         {row[4]:30s} | App: {row[5]:20s}')
        if row[6]:
            print(f'         Details: {row[6][:100]}...')
        print()
else:
    print('NO file transfer related events found!\n')

print('='*80)
print('EVENT TYPE SUMMARY')
print('='*80)

cursor.execute('''
SELECT event_id, COUNT(*) as count
FROM events
GROUP BY event_id
ORDER BY count DESC
LIMIT 20
''')

summary = cursor.fetchall()
print('\nTop 20 event types:\n')
for event_id, count in summary:
    print(f'  {event_id:25s}: {count:>6} events')

conn.close()

print('\n' + '='*80)
print('DIAGNOSIS')
print('='*80)
print('''
If no FILE_COPY, USB_FILE_TRANSFER, or MTP_TRANSFER events are found,
then the file transfer monitoring is NOT detecting any transfers.

This could be due to:
1. Clipboard monitor not working properly
2. Removable drive monitor not detecting the SD card as removable
3. File creation events not being triggered
4. Source/destination path issues

Check if the SD card was properly detected as a removable drive.
''')
