#!/usr/bin/env python3
import os
import sqlite3

print('='*80)
print('DATABASE STATE CHECK')
print('='*80)

print('\nFile existence:')
db_file = 'database/database.db'
risk_file = 'database/riskalert.db'
print(f'  database/database.db exists: {os.path.exists(db_file)}')
print(f'  database/riskalert.db exists: {os.path.exists(risk_file)}')

if os.path.exists(db_file):
    size = os.path.getsize(db_file)
    print(f'    Size: {size} bytes')

if os.path.exists(risk_file):
    size = os.path.getsize(risk_file)
    print(f'    Size: {size} bytes')

print('\n' + '='*80)
print('OPERATIONAL DATABASE (database.db)')
print('='*80)
try:
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    print(f'Tables found: {len(tables)}')
    if len(tables) == 0:
        print('  [EMPTY DATABASE - No tables created yet]')
    else:
        for table in tables:
            cursor.execute(f'SELECT COUNT(*) FROM {table[0]}')
            count = cursor.fetchone()[0]
            print(f'  {table[0]}: {count} rows')
    conn.close()
except Exception as e:
    print(f'ERROR: {e}')

print('\n' + '='*80)
print('RISK ALERT DATABASE (riskalert.db)')
print('='*80)
try:
    conn = sqlite3.connect(risk_file)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    print(f'Tables found: {len(tables)}')
    
    for table in tables:
        table_name = table[0]
        cursor.execute(f'SELECT COUNT(*) FROM {table_name}')
        count = cursor.fetchone()[0]
        print(f'  {table_name}: {count} rows')
        
        if table_name == 'risk_assessments':
            print('\n    Recent risk assessments:')
            cursor.execute('SELECT id, timestamp, risk_level, risk_score, activity_type FROM risk_assessments ORDER BY id DESC LIMIT 5')
            rows = cursor.fetchall()
            for row in rows:
                print(f'      ID {row[0]}: {row[1]} | Level: {row[2]} | Score: {row[3]} | Activity: {row[4]}')
        
        if table_name == 'risk_evidence':
            print('\n    Recent evidence:')
            cursor.execute('SELECT id, risk_id, evidence_text FROM risk_evidence ORDER BY id DESC LIMIT 5')
            rows = cursor.fetchall()
            for row in rows:
                print(f'      ID {row[0]}: Risk {row[1]} | {row[2][:60]}...')
    
    conn.close()
except Exception as e:
    print(f'ERROR: {e}')

print('\n')
