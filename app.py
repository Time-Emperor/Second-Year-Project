import os
import re
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

from scanner_runner import execute_audit_rules
from scoring import calculate_compliance_score
from reporter import export_html_report

try:
    import psutil
except ImportError:
    psutil = None

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-change-this-secret-key-in-prod")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///ahhcs.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.String(50), default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    reports = db.relationship("ScanReport", backref="author", lazy=True)


class ScanReport(db.Model):
    __tablename__ = "scan_reports"
    id = db.Column(db.Integer, primary_key=True)
    user_scan_number = db.Column(db.Integer, nullable=False, default=1)
    timestamp = db.Column(db.String(50), nullable=False)
    score_percentage = db.Column(db.Float, nullable=False)
    passed_checks = db.Column(db.Integer, nullable=False)
    total_checks = db.Column(db.Integer, nullable=False)
    execution_time = db.Column(db.Float, default=0.0)
    report_file = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def ensure_schema():
    db.create_all()
    with db.engine.begin() as conn:
        user_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(users)"))]
        if "created_at" not in user_cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN created_at VARCHAR(50)"))

        report_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(scan_reports)"))]
        if "user_scan_number" not in report_cols:
            conn.execute(text("ALTER TABLE scan_reports ADD COLUMN user_scan_number INTEGER DEFAULT 1"))
        if "execution_time" not in report_cols:
            conn.execute(text("ALTER TABLE scan_reports ADD COLUMN execution_time FLOAT DEFAULT 0.0"))
        if "report_file" not in report_cols:
            conn.execute(text("ALTER TABLE scan_reports ADD COLUMN report_file VARCHAR(255)"))

    for user in User.query.all():
        user_reports = ScanReport.query.filter_by(user_id=user.id).order_by(ScanReport.id.asc()).all()
        for idx, rep in enumerate(user_reports, start=1):
            if rep.user_scan_number != idx:
                rep.user_scan_number = idx
    db.session.commit()


with app.app_context():
    ensure_schema()


def validate_strong_password(password: str) -> tuple[bool, str]:
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter."
    if not re.search(r"\d", password):
        return False, "Password must include at least one number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must include at least one special character."
    return True, ""


def _read_sysfs_int(path: str):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _read_sysfs_str(path: str):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return None


def get_battery_health() -> str:
    for bat_dir in ("/sys/class/power_supply/BAT0", "/sys/class/power_supply/BAT1"):
        if not os.path.isdir(bat_dir):
            continue

        energy_full = _read_sysfs_int(os.path.join(bat_dir, "energy_full"))
        energy_design = _read_sysfs_int(os.path.join(bat_dir, "energy_full_design"))
        charge_full = _read_sysfs_int(os.path.join(bat_dir, "charge_full"))
        charge_design = _read_sysfs_int(os.path.join(bat_dir, "charge_full_design"))

        health_pct = None
        if energy_full and energy_design and energy_design > 0:
            health_pct = round((energy_full / energy_design) * 100)
        elif charge_full and charge_design and charge_design > 0:
            health_pct = round((charge_full / charge_design) * 100)

        charge_pct = _read_sysfs_int(os.path.join(bat_dir, "capacity"))
        status_str = _read_sysfs_str(os.path.join(bat_dir, "status"))

        if charge_pct is None and psutil and hasattr(psutil, "sensors_battery"):
            bat = psutil.sensors_battery()
            if bat is not None:
                charge_pct = round(float(bat.percent), 1)
                if not status_str:
                    status_str = "Charging" if bat.power_plugged else "Discharging"

        if health_pct is not None or charge_pct is not None:
            parts = []
            if health_pct is not None:
                parts.append(f"Health: {health_pct}%")
            if charge_pct is not None:
                c_txt = f"Charge: {charge_pct}%"
                if status_str:
                    c_txt += f" ({status_str})"
                parts.append(c_txt)
            return " | ".join(parts)

    if psutil and hasattr(psutil, "sensors_battery"):
        bat = psutil.sensors_battery()
        if bat is not None:
            state = "Charging" if bat.power_plugged else "Discharging"
            return f"Charge: {round(float(bat.percent), 1)}% ({state})"

    return "No Battery Detected"


def get_ssd_status() -> str:
    pseudo_fs = {"tmpfs", "devtmpfs", "squashfs", "overlay", "proc", "sysfs", "cgroup2"}
    try:
        if psutil:
            seen_devices = set()
            total_bytes = used_bytes = free_bytes = 0

            for part in psutil.disk_partitions(all=False):
                if part.fstype in pseudo_fs or part.device in seen_devices:
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

            if total_bytes <= 0:
                usage = psutil.disk_usage("/")
                total_bytes, used_bytes, free_bytes = usage.total, usage.used, usage.free
        else:
            st = os.statvfs("/")
            total_bytes = st.f_blocks * st.f_frsize
            free_bytes = st.f_bavail * st.f_frsize
            used_bytes = max(0, total_bytes - free_bytes)

        if total_bytes <= 0:
            return "Unavailable"

        total_gb = total_bytes / (1024 ** 3)
        used_gb = used_bytes / (1024 ** 3)
        free_gb = free_bytes / (1024 ** 3)
        used_pct = round((used_bytes / total_bytes) * 100, 1)
        return f"Used: {used_gb:.1f} GB | Left: {free_gb:.1f} GB / {total_gb:.1f} GB ({used_pct}% used)"
    except OSError:
        return "Check Error"


def get_ram_status() -> str:
    try:
        if psutil:
            vm = psutil.virtual_memory()
            total_bytes = vm.total
            avail_bytes = vm.available
            used_bytes = max(0, total_bytes - avail_bytes)
        else:
            mem = {}
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        mem[k.strip()] = int(v.strip().split()[0]) * 1024
            total_bytes = mem.get("MemTotal", 0)
            avail_bytes = mem.get("MemAvailable", 0)
            used_bytes = max(0, total_bytes - avail_bytes)

        if total_bytes <= 0:
            return "Unavailable"

        total_gb = total_bytes / (1024 ** 3)
        used_gb = used_bytes / (1024 ** 3)
        avail_gb = avail_bytes / (1024 ** 3)
        used_pct = round((used_bytes / total_bytes) * 100, 1)
        return f"Used: {used_gb:.1f} GB | Left: {avail_gb:.1f} GB / {total_gb:.1f} GB ({used_pct}% used)"
    except OSError:
        return "Check Error"


def get_system_health() -> dict:
    return {
        "battery": get_battery_health(),
        "ssd": get_ssd_status(),
        "ram": get_ram_status(),
    }


def inject_report_controls(html_path: str, dashboard_url: str):
    if not os.path.exists(html_path):
        return

    with open(html_path, "r", encoding="utf-8") as f:
        content = f.read()

    content = re.sub(
        r"<!-- AHHCS_CONTROLS_START -->.*?<!-- AHHCS_CONTROLS_END -->",
        "",
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
            margin: 18px auto 12px auto;
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
    function ahhcsDetectSectionSeverity(text) {{
        const u = (text || "").toUpperCase().replace(/\\s+/g, " ").trim();
        if (u.includes("HIGH SEVERITY") || /^HIGH\\b/.test(u)) return "HIGH";
        if (u.includes("MEDIUM SEVERITY") || /^MEDIUM\\b/.test(u) || /^MID\\b/.test(u)) return "MEDIUM";
        if (u.includes("LOW SEVERITY") || /^LOW\\b/.test(u)) return "LOW";
        if (u.includes("GENERAL / UNCLASSIFIED") || u.includes("UNCLASSIFIED") || u.includes("NONE SEVERITY") || /^NONE\\b/.test(u)) return "NONE";
        return null;
    }}

    function ahhcsPlaceSeverityBar() {{
        const bar = document.getElementById("ahhcs-severity-bar");
        if (!bar) return;

        const headings = Array.from(document.querySelectorAll("h1, h2, h3, h4"));
        const auditTitle = headings.find(h =>
            h.textContent.toUpperCase().includes("AHHCS HOST HARDENING AUDIT")
        );

        if (auditTitle) {{
            let candidate = auditTitle.parentElement;
            let bestBox = null;
            while (candidate && candidate !== document.body) {{
                const rect = candidate.getBoundingClientRect();
                const hasFindings = candidate.textContent.toUpperCase().includes("SEVERITY FINDINGS") ||
                                    candidate.textContent.toUpperCase().includes("UNCLASSIFIED FINDINGS");
                if (!hasFindings && rect.height > 0 && rect.height < 360) {{
                    bestBox = candidate;
                }}
                if (hasFindings) break;
                candidate = candidate.parentElement;
            }}
            if (bestBox) {{
                bestBox.insertAdjacentElement("afterend", bar);
                return;
            }}
            auditTitle.insertAdjacentElement("afterend", bar);
            return;
        }}

        const firstSec = headings.find(h => ahhcsDetectSectionSeverity(h.textContent) !== null);
        if (firstSec) {{
            firstSec.insertAdjacentElement("beforebegin", bar);
        }}
    }}

    function ahhcsFilterSeverity(level) {{
        const target = level.toUpperCase();
        ahhcsPlaceSeverityBar();

        document.querySelectorAll(".ahhcs-sev-btn").forEach(btn => {{
            btn.classList.toggle("active", btn.getAttribute("data-sev") === target);
        }});

        document.querySelectorAll(".ahhcs-hidden").forEach(el => el.classList.remove("ahhcs-hidden"));
        if (target === "ALL") return;

        const bar = document.getElementById("ahhcs-severity-bar");
        const candidates = Array.from(document.querySelectorAll("h1, h2, h3, h4, div, p, span")).filter(el => {{
            if (el.closest("#ahhcs-top-bar") || el.closest("#ahhcs-severity-bar")) return false;
            if (el.children.length > 3) return false;
            return ahhcsDetectSectionSeverity(el.textContent) !== null;
        }});

        const sectionHeaders = candidates.filter(el => {{
            const txt = el.textContent.toUpperCase();
            return txt.includes("FINDINGS") || txt.includes("SEVERITY") || txt.trim() === "NONE" || txt.trim().startsWith("NONE ");
        }});

        sectionHeaders.forEach((hdr, idx) => {{
            const secSev = ahhcsDetectSectionSeverity(hdr.textContent);
            if (!secSev || secSev === target) return;

            hdr.classList.add("ahhcs-hidden");
            const nextHdr = sectionHeaders[idx + 1] || null;
            let sib = hdr.nextElementSibling;
            while (sib && sib !== nextHdr) {{
                if (sib !== bar && !sib.contains(nextHdr)) {{
                    sib.classList.add("ahhcs-hidden");
                }} else if (sib.contains(nextHdr)) {{
                    for (const child of Array.from(sib.children)) {{
                        if (child === nextHdr || child.contains(nextHdr)) break;
                        child.classList.add("ahhcs-hidden");
                    }}
                    break;
                }}
                sib = sib.nextElementSibling;
            }}
        }});
    }}

    document.addEventListener("DOMContentLoaded", ahhcsPlaceSeverityBar);
    ahhcsPlaceSeverityBar();
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


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("register"))

        valid_pw, pw_msg = validate_strong_password(password)
        if not valid_pw:
            flash(pw_msg, "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect(url_for("register"))

        new_user = User(
            username=username,
            password_hash=generate_password_hash(password, method="pbkdf2:sha256")
        )
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        valid_pw, pw_msg = validate_strong_password(password)
        if not valid_pw:
            flash(f"Login blocked: {pw_msg}", "danger")
            return redirect(url_for("login"))

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user_reports = (
        ScanReport.query
        .filter_by(user_id=current_user.id)
        .order_by(ScanReport.user_scan_number.desc(), ScanReport.id.desc())
        .all()
    )
    return render_template(
        "dashboard.html",
        username=current_user.username,
        reports=user_reports,
        health=get_system_health()
    )


@app.route("/api/system-health")
@login_required
def api_system_health():
    return jsonify(get_system_health())


@app.route("/run-scan", methods=["POST"])
@login_required
def run_scan():
    rules_path = os.path.join(BASE_DIR, "rules.json")
    audit_results, duration = execute_audit_rules(rules_path, "all")
    score_data = calculate_compliance_score(audit_results)

    next_scan_num = ScanReport.query.filter_by(user_id=current_user.id).count() + 1

    new_report = ScanReport(
        user_scan_number=next_scan_num,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        score_percentage=score_data["score_percentage"],
        passed_checks=score_data["passed_checks"],
        total_checks=score_data["total_checks"],
        execution_time=duration,
        report_file="",
        user_id=current_user.id
    )
    db.session.add(new_report)
    db.session.flush()

    filename = f"report_user_{current_user.id}_scan_{new_report.id}.html"
    full_path = os.path.join(REPORTS_DIR, filename)

    export_html_report(audit_results, score_data, full_path)
    inject_report_controls(full_path, url_for("dashboard"))

    new_report.report_file = filename
    db.session.commit()

    return redirect(url_for("view_report", report_id=new_report.id))


@app.route("/report/<int:report_id>")
@login_required
def view_report(report_id: int):
    report = db.session.get(ScanReport, report_id)
    if not report or report.user_id != current_user.id or not report.report_file:
        abort(404)

    safe_name = os.path.basename(report.report_file)
    full_path = os.path.join(REPORTS_DIR, safe_name)
    if not os.path.exists(full_path):
        flash("Report file not found on disk.", "danger")
        return redirect(url_for("dashboard"))

    inject_report_controls(full_path, url_for("dashboard"))
    return send_from_directory(REPORTS_DIR, safe_name)


if __name__ == "__main__":
    app.run(debug=True, port=5000)