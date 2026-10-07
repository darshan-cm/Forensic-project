#!/usr/bin/env python3
import sqlite3

print('Checking operational database schema...')
conn = sqlite3.connect('database/database.db')
cursor = conn.cursor()

# List all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()

print(f'Tables found: {len(tables)}')
for table in tables:
    print(f'  - {table[0]}')

print('\n' + '='*80)
for table in tables:
    table_name = table[0]
    cursor.execute(f'PRAGMA table_info({table_name})')
    columns = cursor.fetchall()
    print(f'\nTable: {table_name}')
    for col in columns:
        print(f'  Column: {col[1]:20s} Type: {col[2]}')
    
    # Get row count
    cursor.execute(f'SELECT COUNT(*) FROM {table_name}')
    count = cursor.fetchone()[0]
    print(f'  Row count: {count}')
    
    # Show sample rows if table has data
    if count > 0:
        cursor.execute(f'SELECT * FROM {table_name} LIMIT 3')
        sample = cursor.fetchall()
        print(f'  Sample rows:')
        for row in sample:
            print(f'    {row}')

conn.close()
