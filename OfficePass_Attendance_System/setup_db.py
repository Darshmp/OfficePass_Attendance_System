import sqlite3
import bcrypt
import os
from dotenv import load_dotenv

load_dotenv()

DB_FILE = 'database.db'
DEFAULT_ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', '1234')  #  Updated environment variable name

SCHEMA = '''
CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    passcode_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER,
    date DATE,
    login_time TEXT,
    logout_time TEXT,
    FOREIGN KEY (employee_id) REFERENCES employees(id),
    UNIQUE(employee_id, date)
);
'''

def setup_database():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    
    with sqlite3.connect(DB_FILE) as conn:
        conn.executescript(SCHEMA)
        
        # Insert sample employees with strong passwords
        employees = [
            ('Darshan M P', bcrypt.gensalt().decode()),
            ('Likitha G', bcrypt.gensalt().decode()),
            ('Shivlingesh', bcrypt.gensalt().decode()),
            ('Priyanka', bcrypt.gensalt().decode())
        ]
        
        for name, salt in employees:
            passcode = os.urandom(8).hex()  #  Increased to 8 bytes (16 hex chars)
            hashed = bcrypt.hashpw(passcode.encode(), salt.encode())
            conn.execute('INSERT INTO employees (name, passcode_hash) VALUES (?, ?)', 
                        (name, hashed.decode()))
            print(f"Created user: {name} with passcode: {passcode}")
        
        # Create admin user
        admin_hash = bcrypt.hashpw(DEFAULT_ADMIN_PASSWORD.encode(), bcrypt.gensalt())
        conn.execute('INSERT INTO admins (username, password_hash) VALUES (?, ?)',
                    ('admin', admin_hash.decode()))
        
        conn.commit()
    print("Database initialized with secure credentials")

if __name__ == '__main__':
    setup_database()