from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from flask_wtf.csrf import CSRFProtect
import sqlite3
from datetime import datetime, date
import bcrypt
import os
from contextlib import closing
import logging
from functools import wraps

# Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    DATABASE = 'database.db'
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'
    SESSION_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour
    WTF_CSRF_TIME_LIMIT = 3600

app = Flask(__name__)
app.config.from_object(Config)
csrf = CSRFProtect(app)
logging.basicConfig(level=logging.INFO)

# Database setup
def init_db():
    with closing(connect_db()) as conn:
        with app.open_resource('schema.sql', mode='r') as f:
            conn.cursor().executescript(f.read())
        conn.commit()

def connect_db():
    def adapt_date(d):
        return d.isoformat()
    def convert_date(s):
        return date.fromisoformat(s.decode())
    
    sqlite3.register_adapter(date, adapt_date)
    sqlite3.register_converter("DATE", convert_date)

    conn = sqlite3.connect(app.config['DATABASE'], detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn

def get_db():
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db

# Security decorators
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Admin access required', 'warning')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated

def employee_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('employee_id'):
            flash('Please login first', 'warning')
            return redirect(url_for('employee_login'))
        return f(*args, **kwargs)
    return decorated

# Routes
@app.route('/')
def home():
    return redirect(url_for('employee_login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            name = request.form['name']
            passcode = request.form['passcode']
            db = get_db()
            
            if db.execute('SELECT id FROM employees WHERE name = ?', (name,)).fetchone():
                flash('Employee already exists', 'danger')
                return redirect(url_for('register'))
            
            hashed = bcrypt.hashpw(passcode.encode('utf-8'), bcrypt.gensalt())
            db.execute('INSERT INTO employees (name, passcode_hash) VALUES (?, ?)',
                      (name, hashed.decode()))
            db.commit()
            flash('Registration successful! Please login', 'success')
            return redirect(url_for('employee_login'))
        
        except Exception as e:
            logging.error(f"Registration error: {str(e)}")
            flash('Registration failed', 'danger')
    
    return render_template('register.html')

@app.route('/employee/login', methods=['GET', 'POST'])
def employee_login():
    if session.get('employee_id'):
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        try:
            name = request.form['name']
            passcode = request.form['passcode']
            db = get_db()
            
            employee = db.execute('''SELECT id, name, passcode_hash FROM employees 
                                   WHERE name = ?''', (name,)).fetchone()
            
            if employee and bcrypt.checkpw(passcode.encode('utf-8'), employee['passcode_hash'].encode('utf-8')):
                today = date.today()
                now = datetime.now().strftime('%H:%M:%S')
                
                # Record login if not already logged in today
                db.execute('''INSERT INTO attendance (employee_id, date, login_time)
                            VALUES (?, ?, ?)
                            ON CONFLICT(employee_id, date) DO NOTHING''',
                         (employee['id'], today, now))
                db.commit()
                
                session['employee_id'] = employee['id']
                session['employee_name'] = employee['name']
                return redirect(url_for('dashboard'))
            
            flash('Invalid credentials', 'danger')
        
        except Exception as e:
            logging.error(f"Login error: {str(e)}")
            flash('Authentication failed', 'danger')
    
    return render_template('employee_login.html')

@app.route('/dashboard')
@employee_required
def dashboard():
    try:
        db = get_db()
        records = db.execute('''SELECT date, login_time, logout_time 
                             FROM attendance 
                             WHERE employee_id = ?
                             ORDER BY date DESC''', 
                          (session['employee_id'],)).fetchall()
        return render_template('dashboard.html', 
                             name=session['employee_name'],
                             records=records)
    except Exception as e:
        logging.error(f"Dashboard error: {str(e)}")
        flash('Failed to load records', 'danger')
        return redirect(url_for('employee_login'))

@app.route('/logout')
@employee_required
def logout():
    try:
        today = date.today()
        now = datetime.now().strftime('%H:%M:%S')
        db = get_db()
        
        db.execute('''UPDATE attendance SET logout_time = ?
                   WHERE employee_id = ? AND date = ?''',
                (now, session['employee_id'], today))
        db.commit()
        
        session.clear()
        flash('Successfully logged out', 'success')
    
    except Exception as e:
        logging.error(f"Logout error: {str(e)}")
        flash('Logout failed', 'danger')
    
    return redirect(url_for('employee_login'))

# Admin routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin'))
    
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            db = get_db()
            admin = db.execute('''SELECT username, password_hash FROM admins 
                                WHERE username = ?''', (username,)).fetchone()
            
            if admin and bcrypt.checkpw(password.encode('utf-8'), admin['password_hash'].encode('utf-8')):
                session.permanent = True
                session['admin_logged_in'] = True
                session['admin_username'] = admin['username']
                return redirect(url_for('admin'))
            
            flash('Invalid credentials', 'danger')
        
        except Exception as e:
            logging.error(f"Admin login error: {str(e)}")
            flash('Authentication failed', 'danger')
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
@admin_required
def admin_logout():
    session.clear()
    flash('Successfully logged out', 'success')
    return redirect(url_for('admin_login'))

@app.route('/admin')
@admin_required
def admin():
    try:
        db = get_db()
        records = db.execute('''SELECT a.date, e.name, a.login_time, a.logout_time 
                             FROM attendance a 
                             JOIN employees e ON a.employee_id = e.id
                             ORDER BY a.date DESC LIMIT 100''').fetchall()
        return render_template('admin.html', records=records)
    except Exception as e:
        logging.error(f"Admin dashboard error: {str(e)}")
        flash('Failed to load attendance records', 'danger')
        return redirect(url_for('admin_login'))

# Teardown
@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)