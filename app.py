#!/usr/bin/env python3
"""
AI Code Scanner Web Application
Flask-based web interface for scanning code vulnerabilities
"""

import os
import json
import logging
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, session
from werkzeug.utils import secure_filename
from scanner import VulnerabilityScanner
from dotenv import load_dotenv
import pyotp
import qrcode
import io
import base64
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length, Regexp

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Security: Session cookie settings
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Set to True in production with HTTPS
app.config['SESSION_TYPE'] = 'filesystem'  # Use server-side session
Session(app)

# Initialize rate limiter
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# Password complexity regex: min 8 chars, 1 upper, 1 lower, 1 digit, 1 special
PASSWORD_REGEX = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};:\"\\|,.<>\/?]).{8,}$'

# Admin action logger
admin_logger = logging.getLogger('admin')
admin_logger.setLevel(logging.INFO)
admin_handler = logging.FileHandler('admin_actions.log')
admin_logger.addHandler(admin_handler)

# Initialize scanner
try:
    scanner = VulnerabilityScanner()
except ValueError as e:
    logger.error(f"Failed to initialize scanner: {str(e)}")
    scanner = None

DB_PATH = os.path.join(os.path.dirname(__file__), 'users.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT NOT NULL
        )''')
        db.execute('''CREATE TABLE IF NOT EXISTS user_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            input_type TEXT NOT NULL, -- snippet, log, or file
            user_input TEXT NOT NULL,
            response TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')
init_db()

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user') or not session.get('2fa_verified'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# WTForms for input validation
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=32)])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8),
        Regexp(PASSWORD_REGEX, message="Password must be at least 8 characters, include upper, lower, digit, and special char.")
    ])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=32)])
    password = PasswordField('Password', validators=[DataRequired()])

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    form = RegisterForm()
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()
        db = get_db()
        if db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
            flash('Username already exists', 'error')
            return render_template('register.html', form=form)
        totp_secret = pyotp.random_base32()
        password_hash = generate_password_hash(password)
        db.execute('INSERT INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?)',
                   (username, password_hash, totp_secret))
        db.commit()
        # Admin log
        admin_logger.info(f"User registered: {username}")
        # Generate QR code for Google Authenticator
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="AI Code Scanner")
        img = qrcode.make(totp_uri)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        qr_b64 = 'data:image/png;base64,' + base64.b64encode(buf.read()).decode('utf-8')
        return render_template('2fa.html', username=username, totp_secret=totp_secret, qr_code=qr_b64, registration=True)
    elif request.method == 'POST':
        flash('Invalid registration details. Please check your input.', 'error')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if not user or not check_password_hash(user['password_hash'], password):
            flash('Invalid username or password', 'error')
            return render_template('login.html', form=form)
        session.clear()  # Clear session to avoid fixation
        session['pending_user'] = username
        return redirect(url_for('two_factor'))
    elif request.method == 'POST':
        flash('Invalid login details. Please check your input.', 'error')
    return render_template('login.html', form=form)

@app.route('/2fa', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def two_factor():
    username = session.get('pending_user')
    if not username:
        return redirect(url_for('login'))
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not user:
        return redirect(url_for('login'))
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        totp = pyotp.TOTP(user['totp_secret'])
        if totp.verify(code):
            session.clear()
            session['user'] = username
            session['2fa_verified'] = True
            admin_logger.info(f"User 2FA success: {username}")
            return redirect(url_for('index'))
        else:
            flash('Invalid 2FA code', 'error')
    return render_template('2fa.html', username=username, registration=False)

@app.route('/logout')
def logout():
    admin_logger.info(f"User logout: {session.get('user')}")
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """Main page with code input form"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_code():
    """Scan submitted code for vulnerabilities"""
    try:
        if scanner is None:
            flash('Scanner not initialized. Please check your Gemini API key.', 'error')
            return redirect(url_for('index'))
        
        # Get code from form
        code = request.form.get('code', '').strip()
        
        if not code:
            flash('Please enter some code to scan', 'error')
            return redirect(url_for('index'))
        
        # Analyze code
        result = scanner.analyze_code(code)
        
        # Log user activity
        if session.get('user'):
            db = get_db()
            db.execute('INSERT INTO user_activity (username, input_type, user_input, response) VALUES (?, ?, ?, ?)',
                       (session['user'], 'snippet', code, json.dumps(result)))
            db.commit()
        
        if 'error' in result:
            flash(f'Analysis failed: {result["error"]}', 'error')
            return redirect(url_for('index'))
        
        # Process results for display
        vulnerabilities = result.get('vulnerabilities', [])
        
        return render_template('results.html', 
                             vulnerabilities=vulnerabilities,
                             code=code,
                             total_vulns=len(vulnerabilities))
        
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for scanning code"""
    try:
        if scanner is None:
            return jsonify({'error': 'Scanner not initialized. Please check your Gemini API key.'}), 500
        
        data = request.get_json()
        
        if not data or 'code' not in data:
            return jsonify({'error': 'No code provided'}), 400
        
        code = data['code'].strip()
        if not code:
            return jsonify({'error': 'Empty code provided'}), 400
        
        # Analyze code
        result = scanner.analyze_code(code)
        
        if 'error' in result:
            return jsonify({'error': result['error']}), 500
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"API scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/upload', methods=['POST'])
def upload_file():
    """Upload and scan a file"""
    try:
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(url_for('index'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('index'))
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            
            # Read file content
            content = file.read().decode('utf-8', errors='ignore')
            
            if not content.strip():
                flash('File is empty', 'error')
                return redirect(url_for('index'))
            
            # Analyze code
            result = scanner.analyze_code(content, filename)
            
            # Log user activity
            if session.get('user'):
                db = get_db()
                db.execute('INSERT INTO user_activity (username, input_type, user_input, response) VALUES (?, ?, ?, ?)',
                           (session['user'], 'file', filename, json.dumps(result)))
                db.commit()
            
            if 'error' in result:
                flash(f'Analysis failed: {result["error"]}', 'error')
                return redirect(url_for('index'))
            
            # Process results for display
            vulnerabilities = result.get('vulnerabilities', [])
            
            return render_template('results.html', 
                                 vulnerabilities=vulnerabilities,
                                 code=content,
                                 filename=filename,
                                 total_vulns=len(vulnerabilities))
        else:
            flash('File type not supported', 'error')
            return redirect(url_for('index'))
            
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/api/upload', methods=['POST'])
def api_upload():
    """API endpoint for file upload and scanning"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not supported'}), 400
        
        filename = secure_filename(file.filename)
        content = file.read().decode('utf-8', errors='ignore')
        
        if not content.strip():
            return jsonify({'error': 'File is empty'}), 400
        
        # Analyze code
        result = scanner.analyze_code(content, filename)
        
        if 'error' in result:
            return jsonify({'error': result['error']}), 500
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"API upload error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/about')
def about():
    """About page with OWASP information"""
    return render_template('about.html')

@app.route('/api/supported-extensions')
def api_supported_extensions():
    """API endpoint to get supported file extensions"""
    if scanner is None:
        extensions = ['.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.php', '.rb', '.go',
                     '.cs', '.cpp', '.c', '.h', '.hpp', '.sql', '.html', '.xml', '.json',
                     '.yaml', '.yml', '.sh', '.bash', '.ps1', '.jsp', '.asp', '.aspx']
    else:
        extensions = scanner.get_supported_extensions()
    
    return jsonify({'extensions': extensions})

def allowed_file(filename):
    """Check if file extension is allowed"""
    if scanner is None:
        # Fallback to basic extension check
        allowed_extensions = ['.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.php', '.rb', '.go',
                            '.cs', '.cpp', '.c', '.h', '.hpp', '.sql', '.html', '.xml', '.json',
                            '.yaml', '.yml', '.sh', '.bash', '.ps1', '.jsp', '.asp', '.aspx']
        _, ext = os.path.splitext(filename.lower())
        return ext in allowed_extensions
    return scanner.should_scan_file(filename)

@app.errorhandler(413)
def too_large(e):
    """Handle file too large error"""
    flash('File too large. Maximum size is 16MB.', 'error')
    return redirect(url_for('index'))

@app.errorhandler(500)
def internal_error(e):
    """Handle internal server errors"""
    logger.error(f"Internal server error: {str(e)}")
    flash('An internal error occurred. Please try again.', 'error')
    return redirect(url_for('index'))

# Template filters
@app.template_filter('get_severity_class')
def get_severity_class(severity):
    """Get CSS class for severity level"""
    classes = {
        'Critical': 'severity-critical',
        'High': 'severity-high',
        'Medium': 'severity-medium',
        'Low': 'severity-low'
    }
    return classes.get(severity, 'severity-unknown')

@app.template_filter('get_severity_icon')
def get_severity_icon(severity):
    """Get icon for severity level"""
    icons = {
        'Critical': '🚨',
        'High': '⚠️',
        'Medium': '⚡',
        'Low': 'ℹ️'
    }
    return icons.get(severity, '❓')

@app.route('/analyze-logs', methods=['POST'])
def analyze_logs():
    """Analyze log files for security threats"""
    try:
        if scanner is None:
            flash('Scanner not initialized. Please check your Gemini API key.', 'error')
            return redirect(url_for('index'))
        
        # Get log content from form
        log_content = request.form.get('logContent', '').strip()
        
        if not log_content:
            flash('Please enter some log content to analyze', 'error')
            return redirect(url_for('index'))
        
        # Analyze logs
        result = scanner.analyze_logs(log_content)
        
        # Log user activity
        if session.get('user'):
            db = get_db()
            db.execute('INSERT INTO user_activity (username, input_type, user_input, response) VALUES (?, ?, ?, ?)',
                       (session['user'], 'log', log_content, json.dumps(result)))
            db.commit()
        
        if 'error' in result:
            flash(f'Log analysis failed: {result["error"]}', 'error')
            return redirect(url_for('index'))
        
        # Process results for display
        threats = result.get('threats', [])
        
        return render_template('log_results.html', 
                             threats=threats,
                             log_content=log_content,
                             total_threats=len(threats))
        
    except Exception as e:
        logger.error(f"Error during log analysis: {str(e)}")
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/api/analyze-logs', methods=['POST'])
def api_analyze_logs():
    """API endpoint for log analysis"""
    try:
        if scanner is None:
            return jsonify({'error': 'Scanner not initialized. Please check your Gemini API key.'}), 500
        
        data = request.get_json()
        
        if not data or 'logContent' not in data:
            return jsonify({'error': 'No log content provided'}), 400
        
        log_content = data['logContent'].strip()
        if not log_content:
            return jsonify({'error': 'Empty log content provided'}), 400
        
        # Analyze logs
        result = scanner.analyze_logs(log_content)
        
        if 'error' in result:
            return jsonify({'error': result['error']}), 500
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"API log analysis error: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Check if Gemini API key is set
    if not os.getenv('GEMINI_API_KEY'):
        print("ERROR: GEMINI_API_KEY environment variable is not set!")
        print("Please set your Gemini API key in the .env file")
        exit(1)
    
    # Run Flask app
    app.run(
        debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true',
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000))
    )
