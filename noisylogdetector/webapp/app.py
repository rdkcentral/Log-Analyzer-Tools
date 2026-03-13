#!/usr/bin/env python3
"""
Flask Web Application for Log Quality Analyzer
"""
import os
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
import yaml

from log_analyzer import load_rules, analyze_log_file, generate_html_report

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Configuration
UPLOAD_FOLDER = 'uploads'
RULES_FILE = '../rules.yml'  # Relative to webapp folder
DATABASE = 'analysis_history.db'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'log'}


def init_db():
    """Initialize the database for analysis history"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            filename TEXT NOT NULL,
            noisy_count INTEGER,
            sensitive_count INTEGER,
            severity_count INTEGER,
            total_issues INTEGER,
            results_json TEXT
        )
    ''')
    conn.commit()
    conn.close()


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def save_to_history(filename, noisy, sensitive, severity, results):
    """Save analysis results to database"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    timestamp = datetime.now().isoformat()
    total_issues = len(noisy) + len(sensitive) + len(severity)
    results_json = json.dumps(results)
    
    cursor.execute('''
        INSERT INTO analysis_history 
        (timestamp, filename, noisy_count, sensitive_count, severity_count, total_issues, results_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, filename, len(noisy), len(sensitive), len(severity), total_issues, results_json))
    
    conn.commit()
    conn.close()


@app.route('/')
def index():
    """Main page with file upload form"""
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and analysis"""
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(request.url)
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        try:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            # Load rules and analyze
            rules = load_rules(RULES_FILE)
            noisy, sensitive, severity = analyze_log_file(filepath, rules)
            
            # Prepare results
            results = {
                'filename': filename,
                'noisy_logs': noisy,
                'sensitive_logs': sensitive,
                'severity_violations': severity,
                'summary': {
                    'total_issues': len(noisy) + len(sensitive) + len(severity),
                    'noisy_count': len(noisy),
                    'sensitive_count': len(sensitive),
                    'severity_count': len(severity)
                }
            }
            
            # Save to history
            save_to_history(filename, noisy, sensitive, severity, results)
            
            # Clean up uploaded file
            os.remove(filepath)
            
            return render_template('results.html', results=results)
            
        except Exception as e:
            flash(f'Error analyzing file: {str(e)}')
            return redirect(url_for('index'))
    else:
        flash('Invalid file type. Please upload .txt or .log files only.')
        return redirect(url_for('index'))


@app.route('/rules')
def view_rules():
    """View and edit rules configuration"""
    try:
        with open(RULES_FILE, 'r') as f:
            rules_content = f.read()
        return render_template('rules.html', rules_content=rules_content)
    except Exception as e:
        flash(f'Error loading rules: {str(e)}')
        return redirect(url_for('index'))


@app.route('/rules', methods=['POST'])
def update_rules():
    """Update rules configuration"""
    try:
        rules_content = request.form['rules_content']
        
        # Validate YAML
        yaml.safe_load(rules_content)
        
        # Save to file
        with open(RULES_FILE, 'w') as f:
            f.write(rules_content)
        
        flash('Rules updated successfully!')
        return redirect(url_for('view_rules'))
        
    except yaml.YAMLError as e:
        flash(f'Invalid YAML format: {str(e)}')
        return render_template('rules.html', rules_content=request.form['rules_content'])
    except Exception as e:
        flash(f'Error updating rules: {str(e)}')
        return render_template('rules.html', rules_content=request.form['rules_content'])


@app.route('/history')
def analysis_history():
    """View analysis history"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, timestamp, filename, noisy_count, sensitive_count, severity_count, total_issues
            FROM analysis_history 
            ORDER BY timestamp DESC 
            LIMIT 50
        ''')
        history = cursor.fetchall()
        conn.close()
        
        return render_template('history.html', history=history)
    except Exception as e:
        flash(f'Error loading history: {str(e)}')
        return redirect(url_for('index'))


@app.route('/history/<int:analysis_id>')
def view_analysis(analysis_id):
    """View specific analysis results"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT results_json FROM analysis_history WHERE id = ?', (analysis_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            results = json.loads(result[0])
            return render_template('results.html', results=results)
        else:
            flash('Analysis not found')
            return redirect(url_for('analysis_history'))
    except Exception as e:
        flash(f'Error loading analysis: {str(e)}')
        return redirect(url_for('analysis_history'))


@app.route('/download/<int:analysis_id>')
def download_report(analysis_id):
    """Download HTML report for specific analysis"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT results_json, filename FROM analysis_history WHERE id = ?', (analysis_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            results = json.loads(result[0])
            filename = result[1]
            
            # Generate HTML report
            html_content = generate_html_report(
                results['noisy_logs'],
                results['sensitive_logs'], 
                results['severity_violations']
            )
            
            # Save to temporary file
            report_filename = f"log_analysis_report_{analysis_id}.html"
            temp_path = os.path.join(UPLOAD_FOLDER, report_filename)
            
            with open(temp_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return send_file(temp_path, as_attachment=True, download_name=report_filename)
        else:
            flash('Analysis not found')
            return redirect(url_for('analysis_history'))
    except Exception as e:
        flash(f'Error generating report: {str(e)}')
        return redirect(url_for('analysis_history'))


# API Endpoints
@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for log analysis"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '' or not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file'}), 400
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Load rules and analyze
        rules = load_rules(RULES_FILE)
        noisy, sensitive, severity = analyze_log_file(filepath, rules)
        
        # Prepare results
        results = {
            'filename': filename,
            'summary': {
                'total_issues': len(noisy) + len(sensitive) + len(severity),
                'noisy_count': len(noisy),
                'sensitive_count': len(sensitive),
                'severity_count': len(severity)
            },
            'noisy_logs': noisy,
            'sensitive_logs': sensitive,
            'severity_violations': severity
        }
        
        # Save to history
        save_to_history(filename, noisy, sensitive, severity, results)
        
        # Clean up uploaded file
        os.remove(filepath)
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/rules', methods=['GET'])
def api_get_rules():
    """API endpoint to get current rules"""
    try:
        rules = load_rules(RULES_FILE)
        return jsonify(rules)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/rules', methods=['PUT'])
def api_update_rules():
    """API endpoint to update rules"""
    try:
        data = request.get_json()
        
        # Validate rules format
        required_keys = ["sensitive_patterns", "failure_keywords", "noisy_log_levels", "required_severity_on_failure"]
        for key in required_keys:
            if key not in data:
                return jsonify({'error': f'Missing required key: {key}'}), 400
        
        # Save rules
        with open(RULES_FILE, 'w') as f:
            yaml.dump(data, f, default_flow_style=False)
        
        return jsonify({'message': 'Rules updated successfully'})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/history')
def api_get_history():
    """API endpoint to get analysis history"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, timestamp, filename, noisy_count, sensitive_count, severity_count, total_issues
            FROM analysis_history 
            ORDER BY timestamp DESC 
            LIMIT 50
        ''')
        history = cursor.fetchall()
        conn.close()
        
        history_list = []
        for row in history:
            history_list.append({
                'id': row[0],
                'timestamp': row[1],
                'filename': row[2],
                'noisy_count': row[3],
                'sensitive_count': row[4],
                'severity_count': row[5],
                'total_issues': row[6]
            })
        
        return jsonify(history_list)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    flash('File too large. Maximum size is 16MB.')
    return redirect(url_for('index'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)