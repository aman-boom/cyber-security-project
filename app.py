from flask import Flask, render_template, request, redirect, session, send_file
import os, datetime, time, sqlite3, re
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.pdfgen import canvas

# modules
from modules.log_analysis import analyze_log
from modules.network_scan import scan_ports
from modules.packet_analysis import analyze_packet, analyze_packet_file
from modules.live_packet import capture_packets
from modules.threat_intel import analyze_threat

app = Flask(__name__)
app.secret_key = "secret123"

UPLOAD_FOLDER = "logs"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ================= DATABASE =================

def init_db():

    conn = sqlite3.connect("users.db")
    cur = conn.cursor()

    # USERS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user'
    )
    """)

    # ACTIVITY LOGS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT,
        action TEXT,
        time TEXT
    )
    """)

    # THREAT LOGS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS threat_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        threat TEXT,
        severity TEXT,
        time TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ================= DEFAULT ADMIN =================

USER_DATA = {
    "username": "kunal sharma",
    "password": "sharma@123"
}

# ================= LOGIN SECURITY =================

login_attempts = {}
lock_time = {}

MAX_ATTEMPTS = 3
LOCK_DURATION = 30

# ================= ACTIVITY =================

activity_log = []

def log_activity(action):

    user = session.get("user", "Unknown")

    current_time = datetime.datetime.now().strftime("%H:%M:%S")

    activity_log.append({
        "time": current_time,
        "action": action
    })

    conn = sqlite3.connect("users.db")
    cur = conn.cursor()

    cur.execute("""
    INSERT INTO activity_logs (user,action,time)
    VALUES (?,?,?)
    """, (user, action, current_time))

    conn.commit()
    conn.close()

# ================= THREAT LOGGER =================

def log_threat(ip, threat, severity):

    conn = sqlite3.connect("users.db")
    cur = conn.cursor()

    cur.execute("""
    INSERT INTO threat_logs (ip,threat,severity,time)
    VALUES (?,?,?,?)
    """, (
        ip,
        threat,
        severity,
        datetime.datetime.now().strftime("%H:%M:%S")
    ))

    conn.commit()
    conn.close()

# ================= LOGIN =================

@app.route("/", methods=["GET","POST"])
def login():

    ip = request.remote_addr

    if ip not in login_attempts:
        login_attempts[ip] = 0
        lock_time[ip] = 0

    if time.time() < lock_time[ip]:
        return render_template(
            "login.html",
            error="Too many attempts. Try later."
        )

    if request.method == "POST":

        name = request.form["name"].lower()
        password = request.form["password"]

        conn = sqlite3.connect("users.db")
        cur = conn.cursor()

        cur.execute(
            "SELECT * FROM users WHERE username=?",
            (name,)
        )

        user = cur.fetchone()

        conn.close()

        # DATABASE LOGIN
        if user and check_password_hash(user[2], password):

            session["user"] = name
            session["role"] = user[3]

            login_attempts[ip] = 0

            log_activity(f"{name} login")

            return redirect("/dashboard")

        # DEFAULT ADMIN
        elif (
            name == USER_DATA["username"]
            and password == USER_DATA["password"]
        ):

            session["user"] = name
            session["role"] = "admin"

            log_activity("Admin login")

            return redirect("/dashboard")

        else:

            login_attempts[ip] += 1

            if login_attempts[ip] >= MAX_ATTEMPTS:

                lock_time[ip] = time.time() + LOCK_DURATION

                return render_template(
                    "login.html",
                    error="Account locked for 30 seconds"
                )

            return render_template(
                "login.html",
                error="Invalid login"
            )

    return render_template("login.html")

# ================= SIGNUP =================

@app.route("/signup", methods=["GET","POST"])
def signup():

    if request.method == "POST":

        name = request.form["name"].lower()
        password = request.form["password"]

        # PASSWORD VALIDATION
        if not re.match(
            r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$',
            password
        ):

            return render_template(
                "signup.html",
                error="Password must contain uppercase, number, special character and 8 chars"
            )

        hashed = generate_password_hash(password)

        conn = sqlite3.connect("users.db")
        cur = conn.cursor()

        try:

            cur.execute("""
            INSERT INTO users (username,password)
            VALUES (?,?)
            """, (name, hashed))

            conn.commit()

        except:

            return render_template(
                "signup.html",
                error="User already exists"
            )

        conn.close()

        return redirect("/")

    return render_template("signup.html")

# ================= DASHBOARD =================

@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/")

    return render_template(
        "index.html",
        activity=activity_log[-10:]
    )

# ================= ADMIN =================

@app.route("/admin")
def admin():

    if session.get("role") != "admin":
        return "Access Denied"

    conn = sqlite3.connect("users.db")
    cur = conn.cursor()

    cur.execute("SELECT username, role FROM users")
    users = cur.fetchall()

    cur.execute("""
    SELECT user, action, time
    FROM activity_logs
    ORDER BY id DESC
    LIMIT 20
    """)
    logs = cur.fetchall()

    cur.execute("""
    SELECT ip, threat, severity, time
    FROM threat_logs
    ORDER BY id DESC
    LIMIT 20
    """)
    threats = cur.fetchall()

    conn.close()

    return render_template(
        "admin.html",
        users=users,
        logs=logs,
        threats=threats
    )

# ================= LOG =================

@app.route("/log", methods=["POST"])
def log_route():

    file = request.files["logfile"]

    path = os.path.join(
        UPLOAD_FOLDER,
        file.filename
    )

    file.save(path)

    result = analyze_log(path)

    log_activity("Log analysis")

    log_threat(
        request.remote_addr,
        "Suspicious Log Activity",
        "HIGH"
    )

    return render_template(
        "result.html",
        title="Log Analysis",
        data=result,
        summary={
            "Open Ports":0,
            "Closed Ports":0,
            "Total Alerts":result["brute_force"],
            "Risk":"High"
        },
        lat=20,
        lon=78,
        alert=True
    )

# ================= NETWORK =================

@app.route("/network", methods=["POST"])
def network():

    ip = request.form["ip"]

    result = scan_ports(ip)

    log_activity("Network scan")

    log_threat(
        ip,
        "Port Scanning",
        "MEDIUM"
    )

    return render_template(
        "result.html",
        title="Network Scan",
        data=result,
        summary={
            "Open Ports":len(result),
            "Closed Ports":100-len(result),
            "Total Alerts":len(result),
            "Risk":"High"
        },
        lat=20,
        lon=78,
        alert=True
    )

# ================= PACKET =================

@app.route("/packet", methods=["POST"])
def packet():

    file = request.files.get("file")

    if file and file.filename:

        path = os.path.join(
            UPLOAD_FOLDER,
            file.filename
        )

        file.save(path)

        result = analyze_packet_file(path)

    else:

        result = analyze_packet(
            request.form.get("packet","")
        )

    log_activity("Packet analysis")

    log_threat(
        request.remote_addr,
        "Suspicious Packet",
        "HIGH"
    )

    return render_template(
        "result.html",
        title="Packet Analysis",
        data=result,
        summary={
            "Open Ports":0,
            "Closed Ports":0,
            "Total Alerts":len(result),
            "Risk":"Medium"
        },
        lat=20,
        lon=78,
        alert=True
    )

# ================= THREAT =================

@app.route("/threat", methods=["POST"])
def threat():

    url = request.form["url"]

    result = analyze_threat(
        url,
        scan_ports
    )

    log_activity("Threat check")

    log_threat(
        request.remote_addr,
        "Threat Intelligence Match",
        "HIGH"
    )

    return render_template(
        "result.html",
        title="Threat Detection",
        data=result["data"],
        summary=result["summary"],
        lat=result["lat"],
        lon=result["lon"],
        alert=True
    )

# ================= LIVE PACKET =================

@app.route("/live")
def live():

    packets = capture_packets()

    log_activity("Live capture")

    return render_template(
        "result.html",
        title="Live Capture",
        data=packets,
        summary={
            "Open Ports":0,
            "Closed Ports":0,
            "Total Alerts":len(packets),
            "Risk":"Medium"
        },
        lat=20,
        lon=78,
        alert=True
    )

# ================= ATTACK SIMULATION =================

@app.route("/simulate/<attack>")
def simulate_attack(attack):

    data = {
        "Attack": attack.upper(),
        "Status": "Simulated Successfully",
        "Severity": "HIGH"
    }

    summary = {
        "Open Ports": 5,
        "Closed Ports": 2,
        "Total Alerts": 7,
        "Risk": "HIGH"
    }

    log_activity(f"{attack} simulation")

    log_threat(
        request.remote_addr,
        attack.upper(),
        "CRITICAL"
    )

    return render_template(
        "result.html",
        title="Attack Simulation",
        data=data,
        summary=summary,
        lat=20,
        lon=78
    )

# ================= AI ASSISTANT =================

@app.route("/ai_assistant")
def ai_assistant():

    advice = [
        "Block suspicious IP immediately.",
        "Enable firewall protection.",
        "Monitor abnormal traffic carefully.",
        "Run deep packet inspection.",
        "Investigate threat logs."
    ]

    return {
        "status":"active",
        "recommendation": advice[
            int(time.time()) % len(advice)
        ]
    }

# ================= PDF REPORT =================

@app.route("/download_report")
def download_report():

    c = canvas.Canvas("report.pdf")

    c.drawString(
        100,
        800,
        "Cyber Security Threat Report"
    )

    c.drawString(
        100,
        760,
        f"Generated: {datetime.datetime.now()}"
    )

    c.drawString(
        100,
        720,
        "Threat Level: HIGH"
    )

    c.drawString(
        100,
        680,
        "SOC Monitoring Active"
    )

    c.save()

    return send_file(
        "report.pdf",
        as_attachment=True
    )

# ================= LOGOUT =================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")

# ================= RUN =================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
