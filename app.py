from flask import Flask, request, redirect, url_for, session, render_template
import sqlite3
import os
import uuid

app = Flask(__name__)
app.secret_key = "supersecretkey123"
app.config["SESSION_COOKIE_HTTPONLY"] = False

DATABASE = "sessionguard.db"

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_token TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Part 1 — attack logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attacker_ip TEXT,
            attacker_ua TEXT,
            victim_username TEXT,
            stolen_token TEXT,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password, role)
        VALUES ('admin', 'admin123', 'admin')
    """)

    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password, role)
        VALUES ('alice', 'user123', 'user')
    """)

    conn.commit()
    conn.close()
    print("✅ Database ready!")

# ─── ROUTES ───────────────────────────────────────────

@app.route("/")
def home():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("home.html", username=session["username"], role=session["role"])

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password)
        ).fetchone()
        conn.close()

        if user:
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]

            token = str(uuid.uuid4())
            ip    = request.remote_addr
            ua    = request.headers.get("User-Agent")

            conn = get_db()
            conn.execute(
                "INSERT INTO sessions (session_token, user_id, ip_address, user_agent) VALUES (?,?,?,?)",
                (token, user["id"], ip, ua)
            )
            conn.commit()
            conn.close()

            session["token"] = token
            print(f"✅ {username} logged in | IP: {ip} | Token: {token[:8]}...")
            return redirect(url_for("home"))
        else:
            error = "Wrong username or password!"

    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    token = session.get("token")
    if token:
        conn = get_db()
        conn.execute("DELETE FROM sessions WHERE session_token = ?", (token,))
        conn.commit()
        conn.close()
    session.clear()
    return redirect(url_for("login"))

# Part 2 — updated check_session_integrity with logging
@app.before_request
def check_session_integrity():
    if request.endpoint in ("login", "logout", "steal", "static", "security_alert", "admin_dashboard"):
        return

    if "token" not in session:
        return

    token = session["token"]
    current_ip = request.remote_addr
    current_ua = request.headers.get("User-Agent")

    conn = get_db()
    record = conn.execute(
        "SELECT * FROM sessions WHERE session_token = ?", (token,)
    ).fetchone()

    if not record:
        conn.close()
        session.clear()
        return redirect(url_for("login"))

    if record["ip_address"] != current_ip or record["user_agent"] != current_ua:
        user = conn.execute(
            "SELECT username FROM users WHERE id = ?", (record["user_id"],)
        ).fetchone()
        victim = user["username"] if user else "unknown"

        conn.execute("""
            INSERT INTO attack_logs (attacker_ip, attacker_ua, victim_username, stolen_token)
            VALUES (?, ?, ?, ?)
        """, (current_ip, current_ua, victim, token[:16]))
        conn.commit()

        print(f"")
        print(f"🚨 HIJACK DETECTED!")
        print(f"   Victim    : {victim}")
        print(f"   Stored IP : {record['ip_address']} | Attacker IP: {current_ip}")
        print(f"   Stored UA : {record['user_agent'][:50]}")
        print(f"   Attack UA : {current_ua[:50]}")
        print(f"")

        conn.execute("DELETE FROM sessions WHERE session_token = ?", (token,))
        conn.commit()
        conn.close()
        session.clear()
        return redirect(url_for("security_alert"))

    conn.close()

@app.route("/comments", methods=["GET", "POST"])
def comments():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()

    if request.method == "POST":
        comment = request.form["comment"]
        user_id  = session["user_id"]
        username = session["username"]
        conn.execute(
            "INSERT INTO comments (user_id, username, content) VALUES (?,?,?)",
            (user_id, username, comment)
        )
        conn.commit()
        conn.close()
        print(f"💬 Comment posted by {username}: {comment[:60]}")
        return redirect(url_for("comments"))

    comments = conn.execute(
        "SELECT username, content FROM comments ORDER BY id DESC"
    ).fetchall()
    conn.close()

    return render_template("comments.html", comments=comments, username=session["username"])

@app.route("/steal")
def steal():
    stolen_cookie = request.args.get("cookie", "")
    print(f"")
    print(f"🚨🚨🚨 STOLEN COOKIE RECEIVED 🚨🚨🚨")
    print(f"💀 {stolen_cookie}")
    print(f"")
    return "", 200

# Part 3 — new routes
@app.route("/security-alert")
def security_alert():
    return render_template("security_alert.html")

@app.route("/admin-dashboard")
def admin_dashboard():
    if "role" not in session or session["role"] != "admin":
        return redirect(url_for("login"))
    conn = get_db()
    logs = conn.execute(
        "SELECT * FROM attack_logs ORDER BY detected_at DESC"
    ).fetchall()
    conn.close()
    return render_template("admin_dashboard.html", logs=logs)

# ──────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    app.run(debug=True)