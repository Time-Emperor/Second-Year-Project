import os
import re
import time
from datetime import datetime

from flask import (
    Flask, render_template, redirect, url_for,
    request, flash, send_from_directory, abort, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text

from parser import load_rule_engine
from ssh_checker import evaluate_ssh_rule
from file_checker import check_file_permissions, check_suid_binary
from scoring import calculate_compliance_score
from reporter import export_html_report

try:
    import psutil
except ImportError:
    psutil = None

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-change-this-secret-key-in-prod')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ahhcs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
os.makedirs(REPORTS_DIR, exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# --- DATABASE MODELS ---
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
    user_scan_number = db.Column(db.Integer, nullable=False, default=1)
    timestamp = db.Column(db.String(50), nullable=False)
    score_percentage = db.Column(db.Float, nullable=False)
    passed_checks = db.Column(db.Integer, nullable=False)
    total_checks = db.Column(db.Integer, nullable=False)
    execution_time = db.Column(db.Float, default=0.0)
    report_file = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def ensure_schema():
    db.create_all()
    with db.engine.begin() as conn:
        user_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(users)"))]
        if 'created_at' not in user_cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN created_at VARCHAR(50)"))

        report_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(scan_reports)"))]
        if 'user_scan_number' not in report_cols:
            conn.execute(text("ALTER TABLE scan_reports ADD COLUMN user_scan_number INTEGER DEFAULT 1"))
        if 'execution_time' not in report_cols:
            conn.execute(text("ALTER TABLE scan_reports ADD COLUMN execution_time FLOAT DEFAULT 0.0"))
        if 'report_file' not in report_cols:
            conn.execute(text("ALTER TABLE scan_reports ADD COLUMN report_file VARCHAR(255)"))

    users = User.query.all()
    for u in users:
        u_reports = ScanReport.query.filter_by(user_id=u.id).order_by(ScanReport.id.asc()).all()
        for idx, r in enumerate(u_reports, start=1):
            if not r.user_scan_number or r.user_scan_number != idx:
                r.user_scan_number = idx
    db.session.commit()


with app.app_context():
    ensure_schema()


# --- SECURITY HELPERS ---
def validate_strong_password(password: str) -> tuple[bool, str]:
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one capital (uppercase) letter."
    if not re.search(r"\d", password):
        return False, "Password must include at least one number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must include at least one special character."
    return True, ""


# --- HARDWARE HEALTH & STORAGE HELPERS ---
def get_system_health() -> dict:
    # 1. Battery Health (design capacity retention + current charge level)
    battery_status = "No Battery Detected"
    health_pct = None
    charge_pct = None
    power_state = None

    for bp in ("/sys/class/power_supply/BAT0", "/sys/class/power_supply/BAT1"):
        if not os.path.isdir(bp):
            continue

        def _read_int(name):
            p = os.path.join(bp, name)
            if os.path.exists(p):
                try:
                    with open(p, "r") as f:
                        return int(f.read().strip())
                except (OSError, ValueError):
                    return None
            return None

        def _read_str(name):
            p = os.path.join(bp, name)
            if os.path.exists(p):
                try:
                    with open(p, "r") as f:
                        return f.read().strip()
                except OSError:
                    return None
            return None

        energy_full = _read_int("energy_full")
        energy_design = _read_int("energy_full_design")
        charge_full = _read_int("charge_full")
        charge_design = _read_int("charge_full_design")

        if energy_full and energy_design and energy_design > 0:
            health_pct = round((energy_full / energy_design) * 100)
        elif charge_full and charge_design and charge_design > 0:
            health_pct = round((charge_full / charge_design) * 100)

        cap_val = _read_int("capacity")
        if cap_val is not None:
            charge_pct = cap_val
        elif psutil and hasattr(psutil, "sensors_battery"):
            bat = psutil.sensors_battery()
            if bat is not None:
                charge_pct = round(float(bat.percent), 1)

        power_state = _read_str("status")
        if not power_state and psutil and hasattr(psutil, "sensors_battery"):
            bat = psutil.sensors_battery()
            if bat is not None:
                power_state = "Charging" if bat.power_plugged else "Discharging"

        if health_pct is not None or charge_pct is not None:
            parts = []
            if health_pct is not None:
                parts.append(f"Health: {health_pct}%")
            if charge_pct is not None:
                charge_str = f"Charge: {charge_pct}%"
                if power_state:
                    charge_str += f" ({power_state})"
                parts.append(charge_str)
            battery_status = " | ".join(parts)
            break

    if battery_status == "No Battery Detected" and psutil and hasattr(psutil, "sensors_battery"):
        bat = psutil.sensors_battery()
        if bat is not None:
            state = "Charging" if bat.power_plugged else "Discharging"
            battery_status = f"Charge: {round(float(bat.percent), 1)}% ({state})"

    # 2. SSD Storage (Used & Left across physical partitions)
    ssd_status = "Unavailable"
    try:
        if psutil:
            seen_devices = set()
            total_bytes = 0
            used_bytes = 0
            free_bytes = 0

            for part in psutil.disk_partitions(all=False):
                if part.fstype in ("tmpfs", "devtmpfs", "squashfs", "overlay", "proc", "sysfs", "cgroup2"):
                    continue
                if part.device in seen_devices:
                    continue
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                except OSError:
                    continue
                if usage.total < 2 * (1024 ** 3):
                    continue
                seen_devices.add(part.device)
                total_bytes += usage.total
                used_bytes += usage.used
                free_bytes += usage.free

            if total_bytes > 0:
                total_gb = total_bytes / (1024 ** 3)
                used_gb = used_bytes / (1024 ** 3)
                free_gb = free_bytes / (1024 ** 3)
                used_pct = round((used_bytes / total_bytes) * 100, 1)
                ssd_status = f"Used: {used_gb:.1f} GB | Left: {free_gb:.1f} GB / {total_gb:.1f} GB ({used_pct}% used)"
            else:
                disk = psutil.disk_usage("/")
                total_gb = disk.total / (1024 ** 3)
                used_gb = disk.used / (1024 ** 3)
                free_gb = disk.free / (1024 ** 3)
                used_pct = round((disk.used / disk.total) * 100, 1) if disk.total > 0 else 0.0
                ssd_status = f"Used: {used_gb:.1f} GB | Left: {free_gb:.1f} GB / {total_gb:.1f} GB ({used_pct}% used)"
        else:
            st = os.statvfs("/")
            total = st.f_blocks * st.f_frsize
            free = st.f_bavail * st.f_frsize
            used = max(0, total - free)
            total_gb = total / (1024 ** 3)
            used_gb = used / (1024 ** 3)
            free_gb = free / (1024 ** 3)
            used_pct = round((used / total) * 100, 1) if total > 0 else 0.0
            ssd_status = f"Used: {used_gb:.1f} GB | Left: {free_gb:.1f} GB / {total_gb:.1f} GB ({used_pct}% used)"
    except OSError:
        ssd_status = "Check Error"

    # 3. RAM Storage (Used & Left)
    ram_status = "Unavailable"
    try:
        if psutil:
            vm = psutil.virtual_memory()
            used_gb = (vm.total - vm.available) / (1024 ** 3)
            total_gb = vm.total / (1024 ** 3)
            avail_gb = vm.available / (1024 ** 3)
            used_pct = round(((vm.total - vm.available) / vm.total) * 100, 1) if vm.total > 0 else 0.0
            ram_status = f"Used: {used_gb:.1f} GB | Left: {avail_gb:.1f} GB / {total_gb:.1f} GB ({used_pct}% used)"
        else:
            meminfo = {}
            with open("/proc/meminfo", "r") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        meminfo[parts[0].strip()] = int(parts[1].strip().split()[0])
            total_kb = meminfo.get("MemTotal", 0)
            avail_kb = meminfo.get("MemAvailable", 0)
            if total_kb > 0:
                used_kb = max(0, total_kb - avail_kb)
                used_pct = round((used_kb / total_kb) * 100, 1)
                ram_status = (
                    f"Used: {used_kb / (1024 ** 2):.1f} GB | "
                    f"Left: {avail_kb / (1024 ** 2):.1f} GB / "
                    f"{total_kb / (1024 ** 2):.1f} GB ({used_pct}% used)"
                )
    except OSError:
        ram_status = "Check Error"

    return {
        "battery": battery_status,
        "ssd": ssd_status,
        "ram": ram_status,
    }


def inject_report_controls(html_path: str, dashboard_url: str):
    if not os.path.exists(html_path):
        return

    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()

    content = re.sub(
        r'<!-- AHHCS_CONTROLS_START -->.*?<!-- AHHCS_CONTROLS_END -->',
        '',
        content,
        flags=re.DOTALL
    )

    controls_html = f"""<!-- AHHCS_CONTROLS_START -->
    <style>
        body {{
            background: #ffffff;
            color: #000000;
            font-family: monospace;
            margin: 0;
            padding: 0 16px 32px 16px;
        }}
        #ahhcs-top-bar {{
            max-width: 1060px;
            margin: 18px auto 14px auto;
            padding: 10px 16px;
            background: #ffffff;
            border: 1px solid #000000;
            font-family: monospace;
            display: flex;
            align-items: center;
            justify-content: flex-start;
        }}
        .ahhcs-back-btn {{
            text-decoration: none;
            background: #000000;
            color: #ffffff;
            padding: 8px 14px;
            font-weight: bold;
            border: 1px solid #000000;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }}
        .ahhcs-back-btn:hover {{
            background: #262626;
        }}
        #ahhcs-severity-bar {{
            max-width: 1060px;
            width: 100%;
            box-sizing: border-box;
            margin: 12px auto 18px auto;
            padding: 10px 14px;
            background: #ffffff;
            border: 1px solid #000000;
            font-family: monospace;
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 8px;
        }}
        .ahhcs-sev-btn {{
            cursor: pointer;
            padding: 6px 12px;
            background: #ffffff;
            font-family: monospace;
            font-weight: bold;
            border: 1px solid #000000;
            color: #000000;
        }}
        .ahhcs-sev-btn[data-sev="ALL"] {{ border-color: #000000; color: #000000; }}
        .ahhcs-sev-btn[data-sev="HIGH"] {{ border-color: #dc2626; color: #dc2626; }}
        .ahhcs-sev-btn[data-sev="MEDIUM"] {{ border-color: #d97706; color: #b45309; }}
        .ahhcs-sev-btn[data-sev="LOW"] {{ border-color: #16a34a; color: #16a34a; }}
        .ahhcs-sev-btn[data-sev="NONE"] {{ border-color: #4b5563; color: #4b5563; }}
        .ahhcs-sev-btn.active {{
            background: #000000 !important;
            color: #ffffff !important;
            border-color: #000000 !important;
        }}
        .ahhcs-hidden {{
            display: none !important;
        }}
    </style>
    <div id="ahhcs-top-bar">
        <a href="{dashboard_url}" class="ahhcs-back-btn">
            <span>&larr;</span>
            <span>Back to Dashboard</span>
        </a>
    </div>

    <div id="ahhcs-severity-bar">
        <span style="color:#000000;font-weight:bold;margin-right:4px;">Severity:</span>
        <button type="button" class="ahhcs-sev-btn active" data-sev="ALL" onclick="ahhcsFilterSeverity('ALL')">[ALL]</button>
        <button type="button" class="ahhcs-sev-btn" data-sev="HIGH" onclick="ahhcsFilterSeverity('HIGH')">[HIGH]</button>
        <button type="button" class="ahhcs-sev-btn" data-sev="MEDIUM" onclick="ahhcsFilterSeverity('MEDIUM')">[MID]</button>
        <button type="button" class="ahhcs-sev-btn" data-sev="LOW" onclick="ahhcsFilterSeverity('LOW')">[LOW]</button>
        <button type="button" class="ahhcs-sev-btn" data-sev="NONE" onclick="ahhcsFilterSeverity('NONE')">[NONE]</button>
    </div>

    <script>
    function ahhcsParseSeverity(raw) {{
        const u = (raw || '').toUpperCase();
        if (u.includes('HIGH')) return 'HIGH';
        if (u.includes('MEDIUM') || u.includes('MID')) return 'MEDIUM';
        if (u.includes('LOW')) return 'LOW';
        if (u.includes('NONE') || u.includes('UNCLASSIFIED')) return 'NONE';
        return null;
    }}

    function ahhcsPlaceBarBelowAuditHeading() {{
        const bar = document.getElementById('ahhcs-severity-bar');
        if (!bar) return;

        const headings = Array.from(document.querySelectorAll('h1, h2, h3, h4'));
        const auditHeading = headings.find(h =>
            h.textContent.toUpperCase().includes('AHHCS HOST HARDENING AUDIT')
        );

        if (auditHeading) {{
            // Find the outer header box/card containing the title, or insert right after the heading
            let target = auditHeading;
            let parent = auditHeading.parentElement;
            while (parent && parent !== document.body) {{
                const text = parent.textContent.toUpperCase();
                if (text.includes('COMPLIANCE SCORE') || text.includes('EXPORT PDF')) {{
                    target = parent;
                }}
                parent = parent.parentElement;
            }}
            target.insertAdjacentElement('afterend', bar);
        }}
    }}

    function ahhcsFilterSeverity(level) {{
        const target = level.toUpperCase();
        ahhcsPlaceBarBelowAuditHeading();

        document.querySelectorAll('.ahhcs-sev-btn').forEach(btn => {{
            btn.classList.toggle('active', btn.getAttribute('data-sev') === target);
        }});

        document.querySelectorAll('.ahhcs-hidden').forEach(el => el.classList.remove('ahhcs-hidden'));
        if (target === 'ALL') return;

        // Walk all elements in document order after the severity bar
        const bar = document.getElementById('ahhcs-severity-bar');
        const allEls = Array.from(document.body.querySelectorAll('*')).filter(el =>
            !el.closest('#ahhcs-top-bar') &&
            !el.closest('#ahhcs-severity-bar') &&
            el.id !== 'ahhcs-top-bar' &&
            el.id !== 'ahhcs-severity-bar' &&
            el.tagName !== 'SCRIPT' &&
            el.tagName !== 'STYLE'
        );

        // First mark section headings (like "HIGH SEVERITY FINDINGS (5)", "MEDIUM SEVERITY FINDINGS (5)")
        const sectionHeadings = allEls.filter(el =>
            ['H1', 'H2', 'H3', 'H4'].includes(el.tagName) &&
            (el.textContent.toUpperCase().includes('SEVERITY FINDINGS') ||
             el.textContent.toUpperCase().includes('SEVERITY') ||
             el.textContent.toUpperCase().trim() === 'NONE')
        );

        // Build map of which elements belong under which section heading
        let currentSectionSev = null;
        allEls.forEach(el => {{
            if (['H1', 'H2', 'H3', 'H4'].includes(el.tagName)) {{
                const secSev = ahhcsParseSeverity(el.textContent);
                if (el.textContent.toUpperCase().includes('SEVERITY') || secSev) {{
                    currentSectionSev = secSev;
                    if (currentSectionSev && currentSectionSev !== target) {{
                        el.classList.add('ahhcs-hidden');
                    }}
                    return;
                }}
            }}

            // Check explicit severity on rule/finding cards (e.g. [SSH-01], data-severity, badges)
            const explicitSev = ahhcsParseSeverity(
                el.getAttribute('data-severity') ||
                el.getAttribute('data-sev') ||
                (el.matches('[class*="sev"], [class*="severity"], .badge, .pill, .finding, .rule-card') ? el.textContent : '')
            );

            // If this element is a standalone card/row under a non-matching section heading
            const isFindingCard = el.matches('.card, .finding, .finding-card, .rule-card, .check-card, .result-card, tr') ||
                (el.parentElement && el.parentElement.matches('.findings, .findings-list, .rules, .cards, tbody'));

            if (isFindingCard && !el.querySelector('.card, .finding, .finding-card, .rule-card, .check-card, .result-card, tr')) {{
                const itemSev = explicitSev || currentSectionSev;
                if (itemSev && itemSev !== target) {{
                    el.classList.add('ahhcs-hidden');
                }}
            }} else if (currentSectionSev && currentSectionSev !== target && !el.contains(bar)) {{
                // If section wrappers are used, hide direct non-matching blocks under the heading
                if (el.parentElement && ['H1', 'H2', 'H3', 'H4'].includes(el.previousElementSibling?.tagName || '')) {{
                    el.classList.add('ahhcs-hidden');
                }}
            }}
        }});
    }}

    document.addEventListener('DOMContentLoaded', ahhcsPlaceBarBelowAuditHeading);
    ahhcsPlaceBarBelowAuditHeading();
    </script>
    <!-- AHHCS_CONTROLS_END -->"""

    if "<body" in content:
        idx = content.find(">", content.find("<body"))
        if idx != -1:
            content = content[:idx + 1] + controls_html + content[idx + 1:]
    else:
        content = controls_html + content

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(content)


# --- ROUTES ---
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        if not username or not password:
            flash('Username and password are required.', 'danger')
            return redirect(url_for('register'))

        valid_pw, pw_msg = validate_strong_password(password)
        if not valid_pw:
            flash(pw_msg, 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

        new_user = User(
            username=username,
            password_hash=generate_password_hash(password, method='pbkdf2:sha256')
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        valid_pw, pw_msg = validate_strong_password(password)
        if not valid_pw:
            flash(f"Login blocked: {pw_msg}", 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))

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
    user_reports = (
        ScanReport.query
        .filter_by(user_id=current_user.id)
        .order_by(ScanReport.user_scan_number.desc(), ScanReport.id.desc())
        .all()
    )
    health = get_system_health()
    return render_template(
        'dashboard.html',
        username=current_user.username,
        reports=user_reports,
        health=health
    )


@app.route('/api/system-health')
@login_required
def api_system_health():
    return jsonify(get_system_health())


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
            audit_results.append({
                "rule_id": rule_id,
                "passed": False,
                "severity": rule.get("severity", "Medium")
            })

    duration = round(time.time() - start_time, 4)
    score_data = calculate_compliance_score(audit_results)

    existing_count = ScanReport.query.filter_by(user_id=current_user.id).count()
    next_scan_num = existing_count + 1

    new_report = ScanReport(
        user_scan_number=next_scan_num,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        score_percentage=score_data['score_percentage'],
        passed_checks=score_data['passed_checks'],
        total_checks=score_data['total_checks'],
        execution_time=duration,
        report_file="",
        user_id=current_user.id
    )
    db.session.add(new_report)
    db.session.flush()

    filename = f"report_user_{current_user.id}_scan_{new_report.id}.html"
    full_path = os.path.join(REPORTS_DIR, filename)

    export_html_report(audit_results, score_data, full_path)
    inject_report_controls(full_path, url_for('dashboard'))

    new_report.report_file = filename
    db.session.commit()

    return redirect(url_for('view_report', report_id=new_report.id))


@app.route('/report/<int:report_id>')
@login_required
def view_report(report_id: int):
    report = db.session.get(ScanReport, report_id)
    if not report or report.user_id != current_user.id or not report.report_file:
        abort(404)

    full_path = os.path.join(REPORTS_DIR, os.path.basename(report.report_file))
    if not os.path.exists(full_path):
        flash('Report file not found on disk.', 'danger')
        return redirect(url_for('dashboard'))

    inject_report_controls(full_path, url_for('dashboard'))
    return send_from_directory(REPORTS_DIR, os.path.basename(full_path))


if __name__ == '__main__':
    app.run(debug=True, port=5000)