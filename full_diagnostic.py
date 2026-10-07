#!/usr/bin/env python3
import os
import sqlite3

print('='*80)
print('COMPREHENSIVE DATABASE DIAGNOSTIC')
print('='*80)

# Check all database files in project
database_files = {
    'database/database.db': 'database/database.db',
    'database/forensic.db': 'database/forensic.db',
    'database/riskalert.db': 'database/riskalert.db',
}

print('\nFile existence check:')
for name, path in database_files.items():
    exists = os.path.exists(path)
    size = os.path.getsize(path) if exists else 0
    print(f'  {name:30s} exists: {exists:5} | size: {size:>10} bytes')

print('\n' + '='*80)
print('FORENSIC.DB (OPERATIONAL DATABASE)')
print('='*80)

forensic_db = 'database/forensic.db'
if os.path.exists(forensic_db):
    try:
        conn = sqlite3.connect(forensic_db)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        print(f'\nTables found: {len(tables)}')
        
        for table in tables:
            table_name = table[0]
            cursor.execute(f'SELECT COUNT(*) FROM {table_name}')
            count = cursor.fetchone()[0]
            print(f'  {table_name:20s}: {count:>10} rows')
            
            if table_name == 'events' and count > 0:
                print('\n  Recent events:')
                cursor.execute('SELECT id, timestamp, source, event_id, action, application FROM events ORDER BY id DESC LIMIT 10')
                rows = cursor.fetchall()
                for row in rows:
                    print(f'    ID {row[0]:5d} | {row[1]} | {row[2]:20s} | {row[3]:20s} | {row[4]:25s}')
        
        conn.close()
    except Exception as e:
        print(f'ERROR: {e}')
else:
    print('forensic.db does not exist')

print('\n' + '='*80)
print('RISKALERT.DB (RISK AUDIT DATABASE)')
print('='*80)

risk_db = 'database/riskalert.db'
if os.path.exists(risk_db):
    try:
        conn = sqlite3.connect(risk_db)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        print(f'\nTables found: {len(tables)}')
        
        for table in tables:
            table_name = table[0]
            cursor.execute(f'SELECT COUNT(*) FROM {table_name}')
            count = cursor.fetchone()[0]
            print(f'  {table_name:20s}: {count:>10} rows')
        
        conn.close()
    except Exception as e:
        print(f'ERROR: {e}')
else:
    print('riskalert.db does not exist')

print('\n' + '='*80)
print('CONCLUSION')
print('='*80)
print('\nIf forensic.db has 0 rows, the monitoring was NOT running during the real test.')
print('If riskalert.db has 0 rows, no risk assessments were generated.')
print()
