import sqlite3
import bcrypt
import os
from dotenv import load_dotenv

load_dotenv()

DB_FILE = 'database.db'
DEFAULT_ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', '1234')
DEFAULT_ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'darshanmpreddy@gmail.com')

SCHEMA = '''
CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    passcode TEXT NOT NULL,
    department TEXT,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT  NOT NULL
);

CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id TEXT NOT NULL, 
    date TEXT,
    login_time TEXT,
    logout_time TEXT,
    session_type TEXT DEFAULT 'work' CHECK(session_type IN (
        'work', 'break', 'logout', 'paid_leave', 'loss_of_pay', 
        'half_day', 'holiday', 'morning_half', 'afternoon_half', 'week_off'
    )),
    status TEXT DEFAULT 'pending',
    FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
);

CREATE TABLE IF NOT EXISTS holidays (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT UNIQUE NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS employee_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER NOT NULL,
    month INTEGER NOT NULL,
    year INTEGER NOT NULL,
    paid_leaves INTEGER DEFAULT 0,
    loss_of_pay INTEGER DEFAULT 0,
    half_days INTEGER DEFAULT 0,
    week_offs INTEGER DEFAULT 0,
    FOREIGN KEY (employee_id) REFERENCES employees(id),
    UNIQUE(employee_id, month, year)
);

CREATE TABLE IF NOT EXISTS employee_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER UNIQUE NOT NULL,
    photo_path TEXT,
    id_card_path TEXT,
    date_of_birth DATE,
    FOREIGN KEY (employee_id) REFERENCES employees(id)
);

CREATE TRIGGER IF NOT EXISTS restore_leave_count 
AFTER DELETE ON attendance 
WHEN OLD.status = 'approved'
BEGIN
    UPDATE employee_stats
    SET paid_leaves = paid_leaves - 1 
    WHERE employee_id = OLD.employee_id 
        AND month = CAST(strftime('%m', OLD.date) AS INTEGER)
        AND year = CAST(strftime('%Y', OLD.date) AS INTEGER)
        AND OLD.session_type = 'paid_leave';
    
    UPDATE employee_stats
    SET half_days = half_days - 1 
    WHERE employee_id = OLD.employee_id 
        AND month = CAST(strftime('%m', OLD.date) AS INTEGER)
        AND year = CAST(strftime('%Y', OLD.date) AS INTEGER)
        AND OLD.session_type IN ('morning_half', 'afternoon_half');
    
    UPDATE employee_stats
    SET week_offs = week_offs - 1 
    WHERE employee_id = OLD.employee_id 
        AND month = CAST(strftime('%m', OLD.date) AS INTEGER)
        AND year = CAST(strftime('%Y', OLD.date) AS INTEGER)
        AND OLD.session_type = 'week_off';
    
    UPDATE employee_stats
    SET loss_of_pay = loss_of_pay - 1 
    WHERE employee_id = OLD.employee_id 
        AND month = CAST(strftime('%m', OLD.date) AS INTEGER)
        AND year = CAST(strftime('%Y', OLD.date) AS INTEGER)
        AND OLD.session_type = 'loss_of_pay';
END;
'''

def setup_database():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    
    with sqlite3.connect(DB_FILE) as conn:
        conn.executescript(SCHEMA)

        # Insert sample employees with text-based IDs
        employees = [
            ('ET2025001', 'Thoshitha R Kumar', '1234', 'Digital Marketing'),
            ('ET2025002', 'Darshan M P', '1234', 'IT'),
            ('ET2025003', 'Likitha G', '1234', 'Civil'),
            ('ET2025004', 'Priyanka', '1234', 'Management'),
            ('ET2025005', 'Mahalingha Swamy', '1234', 'Mechanical')  
        ]

        for emp_id, name, passcode, department in employees:
            conn.execute(
                'INSERT INTO employees (employee_id, name, passcode, department) VALUES (?, ?, ?, ?)',
                (emp_id, name, passcode, department)
            )
            print(f"👤 Created employee: ID={emp_id} | Name={name} | Passcode={passcode} | Department={department}")

        # Insert two admin accounts with same password and email
        hashed_password = bcrypt.hashpw(DEFAULT_ADMIN_PASSWORD.encode('utf-8'), bcrypt.gensalt())
        
        # First admin
        conn.execute(
            'INSERT INTO admins (username, password, email) VALUES (?, ?, ?)',
            ('admin1', hashed_password.decode('utf-8'), DEFAULT_ADMIN_EMAIL)
        )
        print(f"👤 Created admin: username=admin1 | password={DEFAULT_ADMIN_PASSWORD} | email={DEFAULT_ADMIN_EMAIL}")
        
        # Second admin
        conn.execute(
            'INSERT INTO admins (username, password, email) VALUES (?, ?, ?)',
            ('admin2', hashed_password.decode('utf-8'), DEFAULT_ADMIN_EMAIL)
        )
        print(f"👤 Created admin: username=admin2 | password={DEFAULT_ADMIN_PASSWORD} | email={DEFAULT_ADMIN_EMAIL}")

if __name__ == '__main__':
    setup_database()