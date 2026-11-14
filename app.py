import os
import time
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Import your existing AHHCS audit components
from parser import load_rule_engine
from ssh_checker import evaluate_ssh_rule
from file_checker import check_file_permissions, check_suid_binary
from scoring import calculate_compliance_score
from reporter import export_html_report

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secure-random-secret-key-change-me'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ahhcs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- 1. DATABASE MODELS (ERD Implementation Alignment) ---
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.String(50), default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    reports = db.relationship('ScanReport', backref='author', lazy=True)

class ScanReport(db.Model):
    __tablename__ = 'scan_reports'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(50), nullable=False)
    score_percentage = db.Column(db.Float, nullable=False)
    passed_checks = db.Column(db.Integer, nullable=False)
    total_checks = db.Column(db.Integer, nullable=False)
    execution_time = db.Column(db.Float, default=0.0)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Create database tables automatically on startup
with app.app_context():
    db.create_all()

# --- 2. AUTHENTICATION & APP ROUTES ---

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            flash('Username already exists. Please choose another.', 'danger')
            return redirect(url_for('register'))
            
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch user scan history from DB
    user_reports = ScanReport.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', username=current_user.username, reports=user_reports)

@app.route('/run-scan', methods=['POST'])
@login_required
def run_scan():
    rules_path = 'rules.json'
    rules = load_rule_engine(rules_path)
    audit_results = []
    
    start_time = time.time()
    for rule in rules:
        category = rule.get("category")
        rule_id = rule.get("rule_id", "UNKNOWN")
        try:
            if category == "ssh":
                config_path = "/etc/ssh/sshd_config" if os.path.exists("/etc/ssh/sshd_config") else "etc/ssh/sshd_config"
                result = evaluate_ssh_rule(config_path, rule)
            elif category == "file_permissions":
                result = check_file_permissions(rule.get("path"), rule.get("expected_octal"), rule)
            elif category == "suid":
                result = check_suid_binary(rule.get("path"), rule)
            else:
                continue
            audit_results.append(result)
        except Exception:
            audit_results.append({"rule_id": rule_id, "passed": False, "severity": rule.get("severity", "Medium")})
            
    duration = round(time.time() - start_time, 4)
    score_data = calculate_compliance_score(audit_results)
    
    # Export HTML report uniquely for user
    report_filename = f"report_user_{current_user.id}.html"
    export_html_report(audit_results, score_data, report_filename)
    
    # Save record to database with execution time
    new_report = ScanReport(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        score_percentage=score_data['score_percentage'],
        passed_checks=score_data['passed_checks'],
        total_checks=score_data['total_checks'],
        execution_time=duration,
        user_id=current_user.id
    )
    db.session.add(new_report)
    db.session.commit()
    
    return send_from_directory('.', report_filename)

if __name__ == '__main__':
    app.run(debug=True, port=5000)