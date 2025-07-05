#!/usr/bin/env python3
"""
AI Code Scanner Web Application
Flask-based web interface for scanning code vulnerabilities
"""

import os
import json
import logging
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
from werkzeug.utils import secure_filename
from scanner import VulnerabilityScanner
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize scanner
try:
    scanner = VulnerabilityScanner()
except ValueError as e:
    logger.error(f"Failed to initialize scanner: {str(e)}")
    scanner = None

@app.route('/')
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
