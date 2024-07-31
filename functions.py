import sqlite3
from pathlib import Path
from re import match

def database_found() -> bool:
    file_path = Path('database.db')
    if file_path.exists():
        return True
    else:
        return False


def create_database():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    sql = '''
    CREATE TABLE users (
    user_id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password_hash TEXT,
    join_date TEXT);
    '''
    cursor.execute(sql)
    sql = '''
    CREATE TABLE journal_logs (
    log_id INTEGER PRIMARY KEY,
    user_id INTEGER,
    title TEXT,
    log TEXT,
    date TEXT);
    '''
    cursor.execute(sql)
    conn.commit()
    conn.close()

def validate_email_syntax(email):
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return match(pattern, email) is not None