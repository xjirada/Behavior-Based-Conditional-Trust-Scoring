# app.py
import os
import sqlite3
import uuid
import re
import time
from functools import wraps
from flask import (
    Flask, g, render_template, request, redirect, url_for,
    session, make_response, flash
)
from werkzeug.security import generate_password_hash, check_password_hash

# -------------------------
# Paths and app init
# -------------------------
BASE_DIR  = os.path.abspath(os.path.dirname(__file__))
DATA_DIR  = os.path.join(BASE_DIR, "data")
DB        = os.path.join(DATA_DIR, "poc_zta.db")
SCHEMA    = os.path.join(BASE_DIR, "schema.sql")
os.makedirs(DATA_DIR, exist_ok=True)

SECRET_KEY = os.environ.get("SECRET_KEY", "lemao123")  # change for prod

app = Flask(__name__, template_folder="templates")
app.secret_key = SECRET_KEY

# -------------------------
# Database helpers
# -------------------------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(query, args=()):
    con = get_db()
    cur = con.execute(query, args)
    con.commit()
    return cur.lastrowid

# -------------------------
# Init DB (if needed) + demo users
# -------------------------
def init_db():
    # create tables from schema.sql
    with open(SCHEMA, "r") as f:
        get_db().executescript(f.read())

    # admin1 start score 50, admin2 100
    demo_users = [
        ("admin1", "password1", "admin1@example.com", 50),
        ("admin2", "password2", "admin2@example.com", 100),
    ]
    for uname, plain_pw, email, start_score in demo_users:
        exists = query_db("SELECT id FROM users WHERE username = ?", (uname,), one=True)
        if not exists:
            pw_hash = generate_password_hash(plain_pw)
            device_id = str(uuid.uuid4())
            execute_db(
                "INSERT INTO users (username, password_hash, email, score, device_id) VALUES (?, ?, ?, ?, ?)",
                (uname, pw_hash, email, start_score, device_id)
            )
    print("[INIT] DB initialized and demo users ensured")

# -------------------------
# Auth + helpers
# -------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        # kalau lagi dihukum puzzle, semua route protected (kecuali /puzzle) diarahkan ke puzzle
        if session.get("puzzle_required") and request.endpoint != "puzzle":
            return redirect(url_for("puzzle"))
        return f(*args, **kwargs)
    return decorated

def current_user():
    if "user_id" not in session:
        return None
    return query_db("SELECT * FROM users WHERE id = ?", (session["user_id"],), one=True)

# -------------------------
# Simple scoring engine
# -------------------------
SCORE_KEYWORD_DELTAS = {
    "sqlmap": -20,
    "sqli": -15,
    "union select": -15,
    "select * from": -10,
    "admin' --": -20,
    "xss": -10,
    "<script>": -10,
    "nmap": -12,
    "massscan": -12,
    "bruteforce": -18,
    "password spray": -15,
    "login failed": -5,
    "failed login": -5,
    "error": -2,
    "suspicious": -7,
    "sql": -8,
    "payload": -8,
    "human-ok": +5,
}

def clamp_score(s): 
    return max(0, min(100, s))

def map_input_to_delta(text):
    text_low = (text or "").lower()
    delta = 0
    for token, change in SCORE_KEYWORD_DELTAS.items():
        if token in text_low:
            delta += change
    numbers = len(re.findall(r"\d{3,}", text_low))
    if numbers > 3:
        delta -= 5
    # kalau ada input tapi ga kena keyword, anggap -1 (sedikit curiga)
    if delta == 0 and text_low.strip():
        delta = -1
    return delta

PUNISHMENT_TEXT = [
    (91, 100, "Trusted — no action."),
    (76, 90, "Low suspicion — passive monitoring."),
    (61, 75, "Mild suspicion — captcha required for sensitive actions."),
    (46, 60, "Medium suspicion — progressive delays on responses."),
    (31, 45, "High suspicion — privileged actions disabled; manual review queued."),
    (16, 30, "Very high suspicion — session isolated and honeypoting enabled."),
    (0, 15, "CRITICAL — account soft-locked; manual restore required."),
]

def get_punishment_text(score):
    for lo, hi, txt in PUNISHMENT_TEXT:
        if lo <= score <= hi:
            return txt
    return "Unknown"

# -------------------------
# Routes
# -------------------------
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = query_db("SELECT * FROM users WHERE username = ?", (username,), one=True)
        if not user or not check_password_hash(user["password_hash"], password):
            flash("invalid credentials", "danger")
            return render_template("login.html")
        cookie_device = request.cookies.get("device_id")
        bound_device = user["device_id"]
        session["user_id"] = user["id"]
        resp = make_response(redirect(url_for("dashboard")))
        if not cookie_device:
            resp.set_cookie("device_id", bound_device, httponly=True, samesite="Lax")
        flash("logged in", "success")
        return resp
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("logged out", "info")
    return redirect(url_for("login"))

@app.before_request
def load_user_and_inject():
    g.user = current_user()

@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    user = g.user
    score = user["score"]
    punishment = get_punishment_text(score)

    # ambil event terakhir user ini
    last = query_db(
        "SELECT delta, created_at FROM events WHERE user_id = ? ORDER BY id DESC LIMIT 1",
        (user["id"],),
        one=True
    )
    last_delta = last["delta"] if last else None
    prev_score = None
    if last_delta is not None:
        prev_score = clamp_score(score - last_delta)

    return render_template(
        "dashboard.html",
        score=score,
        punishment=punishment,
        username=user["username"],
        last_delta=last_delta,
        prev_score=prev_score,
    )

@app.route("/test_input", methods=["POST"])
@login_required
def test_input():
    user = g.user
    text = request.form.get("test_input", "")
    delta = map_input_to_delta(text)
    new_score = clamp_score(user["score"] + delta)

    execute_db("UPDATE users SET score = ? WHERE id = ?", (new_score, user["id"]))
    execute_db("INSERT INTO events (user_id, raw_input, delta) VALUES (?, ?, ?)",
               (user["id"], text, delta))
    punishment = get_punishment_text(new_score)

    # ---------------------------
    # PUNISHMENT ENGINE (DEMO)
    # ---------------------------
    # Anggap: delta < 0 = payload/suspicious ke-detect oleh "SIEM"
    if delta < 0:
        # Punishment 1: DELAY 5 DETIK
        time.sleep(5)

        # Punishment 2: PUZZLE kalau cukup parah
        # trigger kalau skor jatuh ke <= 45 atau delta besar (<= -15)
        if new_score <= 45 or delta <= -15:
            session["puzzle_required"] = True
            session["puzzle_correct_once"] = False
            flash("Suspicious activity detected. Puzzle verification required.", "warning")
            return redirect(url_for("puzzle"))

    flash(f"Processed input (delta {delta:+d}). New score: {new_score}. Action: {punishment}", "info")
    return redirect(url_for("dashboard"))

# Reset current user's score to 100 (demo)
@app.route("/reset_score", methods=["POST"])
@login_required
def reset_score():
    user = g.user
    execute_db("UPDATE users SET score = ? WHERE id = ?", (100, user["id"]))
    execute_db("INSERT INTO events (user_id, raw_input, delta) VALUES (?, ?, ?)",
               (user["id"], "[reset_score_100]", 0))
    flash("Score reset to 100 (demo).", "success")
    return redirect(url_for("dashboard"))

# Reset current user's score to 50 (demo)
@app.route("/reset_score_50", methods=["POST"])
@login_required
def reset_score_50():
    user = g.user
    execute_db("UPDATE users SET score = ? WHERE id = ?", (50, user["id"]))
    execute_db("INSERT INTO events (user_id, raw_input, delta) VALUES (?, ?, ?)",
               (user["id"], "[reset_score_50]", 0))
    flash("Score reset to 50 (demo).", "success")
    return redirect(url_for("dashboard"))

# -------------------------
# Puzzle challenge
# -------------------------
@app.route("/puzzle", methods=["GET", "POST"])
@login_required
def puzzle():
    import random

    # Generate puzzle (simple math) kalau GET atau belum ada di session
    if request.method == "GET" or "puzzle_answer" not in session:
        a, b, c = random.randint(1, 9), random.randint(1, 9), random.randint(1, 9)
        question = f"{a} + {b} × {c}"
        answer = a + b * c
        session["puzzle_question"] = question
        session["puzzle_answer"] = str(answer)
        return render_template("puzzle.html", question=question)

    # POST: check jawaban
    user_answer = (request.form.get("answer") or "").strip()
    real_answer = session.get("puzzle_answer")
    correct_once = session.get("puzzle_correct_once", False)

    if user_answer == real_answer:
        if not correct_once:
            # First correct: pura-pura SALAH (biar ngeselin)
            session["puzzle_correct_once"] = True
            flash("Incorrect answer, try again.", "danger")
        else:
            # Second correct: baru dilepas
            session.pop("puzzle_required", None)
            session.pop("puzzle_correct_once", None)
            session.pop("puzzle_answer", None)
            session.pop("puzzle_question", None)
            flash("Puzzle solved. You may continue.", "success")
            return redirect(url_for("dashboard"))
    else:
        # Salah beneran -> progress di-reset
        session["puzzle_correct_once"] = False
        flash("Incorrect answer, try again.", "danger")

    # Setiap attempt, generate puzzle baru lagi (extra annoying)
    a, b, c = random.randint(1, 9), random.randint(1, 9), random.randint(1, 9)
    question = f"{a} + {b} × {c}"
    answer = a + b * c
    session["puzzle_question"] = question
    session["puzzle_answer"] = str(answer)
    return render_template("puzzle.html", question=question)

@app.route("/admin/events")
def admin_events():
    rows = query_db("SELECT e.id, u.username, e.raw_input, e.delta, e.created_at FROM events e JOIN users u ON e.user_id = u.id ORDER BY e.id DESC LIMIT 200")
    return render_template("admin_events.html", rows=rows)

# -------------------------
# Boot / ensure db
# -------------------------
if __name__ == "__main__":
    try:
        query_db("SELECT 1 FROM users LIMIT 1")
    except Exception:
        with app.app_context():
            print("Initializing DB...")
            init_db()
    app.run(debug=True, host="127.0.0.1", port=5000)
