import os
import sqlite3
import uuid
import time
from functools import wraps
from siem_logic import analyze_request


from flask import (
    Flask, g, render_template, request, redirect, url_for,
    session, make_response, flash
)
from werkzeug.security import generate_password_hash, check_password_hash

from trust_engine import (
    TrustEngine,
    TrustAction,
    clamp_score,
    score_to_profile,
    score_to_label,
)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB = os.path.join(DATA_DIR, "poc_zta.db")
SCHEMA = os.path.join(BASE_DIR, "schema.sql")
os.makedirs(DATA_DIR, exist_ok=True)

SECRET_KEY = os.environ.get("SECRET_KEY", "lemao123")  # ganti di prod

app = Flask(__name__, template_folder="templates")
app.secret_key = SECRET_KEY

trust_engine = TrustEngine()

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
    
def init_db():
    # create tables from schema.sql
    with open(SCHEMA, "r") as f:
        get_db().executescript(f.read())

    # demo users buat PoC
    demo_users = [
        ("admin1", "password1", "admin1@example.com", 50),
        ("admin2", "password2", "admin2@example.com", 100),
    ]
    for uname, plain_pw, email, start_score in demo_users:
        exists = query_db(
            "SELECT id FROM users WHERE username = ?",
            (uname,),
            one=True,
        )
        if not exists:
            pw_hash = generate_password_hash(plain_pw)
            device_id = str(uuid.uuid4())
            execute_db(
                "INSERT INTO users (username, password_hash, email, score, device_id) "
                "VALUES (?, ?, ?, ?, ?)",
                (uname, pw_hash, email, start_score, device_id),
            )
    print("[INIT] DB initialized and demo users ensured")

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))

        if session.get("cooldown"):
            session.pop("cooldown", None)

        cooldown_until = session.get("cooldown_until")
        if cooldown_until and request.endpoint == "test_input":
            import time as _time

            now = _time.time()
            if now < float(cooldown_until):
                remaining = int(float(cooldown_until) - now)
                if remaining < 1:
                    remaining = 1
                flash(
                    f"You are in cooldown, please wait ~{remaining} seconds "
                    f"before sending more events.",
                    "warning",
                )
                return redirect(url_for("dashboard"))
            else:
              
                session.pop("cooldown_until", None)
                
        if session.get("puzzle_required") and request.endpoint != "puzzle":
            return redirect(url_for("puzzle"))

        return f(*args, **kwargs)

    return decorated



def current_user():
    if "user_id" not in session:
        return None
    return query_db(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],),
        one=True,
    )


@app.before_request
def load_user_and_inject():
    g.user = current_user()


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("register.html")

        existing = query_db(
            "SELECT id FROM users WHERE username = ?",
            (username,),
            one=True,
        )
        if existing:
            flash("Username already taken.", "danger")
            return render_template("register.html")

        pw_hash = generate_password_hash(password)
        device_id = str(uuid.uuid4())
    
        start_score = 80

        execute_db(
            "INSERT INTO users (username, password_hash, email, score, device_id) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, pw_hash, email, start_score, device_id),
        )

        resp = make_response(redirect(url_for("login")))
        resp.set_cookie("device_id", device_id, httponly=True, samesite="Lax")
        flash("Registration successful. Please log in.", "success")
        return resp

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        user = query_db(
            "SELECT * FROM users WHERE username = ?",
            (username,),
            one=True,
        )
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid credentials.", "danger")
            return render_template("login.html")

        cookie_device = request.cookies.get("device_id")
        bound_device = user["device_id"]

        session.clear()
        session["user_id"] = user["id"]

        resp = make_response(redirect(url_for("dashboard")))

     
        if not cookie_device:
            resp.set_cookie(
                "device_id",
                bound_device,
                httponly=True,
                samesite="Lax",
            )

        flash("Logged in.", "success")
        return resp

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    user = g.user
    score = user["score"]

    profile = score_to_profile(score)
    punishment = score_to_label(score)

    last = query_db(
        "SELECT delta, raw_input, created_at "
        "FROM events WHERE user_id = ? ORDER BY id DESC LIMIT 1",
        (user["id"],),
        one=True,
    )
    last_delta = last["delta"] if last else None
    last_input = last["raw_input"] if last else None
    prev_score = None
    if last_delta is not None:
        prev_score = clamp_score(score - last_delta)

    return render_template(
        "dashboard.html",
        score=score,
        profile=profile,
        punishment=punishment,
        username=user["username"],
        last_delta=last_delta,
        last_input=last_input,
        prev_score=prev_score,
    )


@app.route("/test_input", methods=["POST"])
@login_required
def test_input():
    """
    Simulate SIEM/UEBA event:
    - treat text as log/payload
    - analyze dengan siem_logic -> severity + meta
    - trust_engine.apply() -> new_score + action
    """
    user = g.user
    text = request.form.get("test_input", "")

    category = "app"

    if text.lower().startswith("[social]"):
        category = "social"
        text = text[len("[social]") : ].strip()

    severity, meta = analyze_request(
        raw_text=text,
        source_ip=request.remote_addr or "unknown",
        username=user["username"],
        endpoint=request.path,
        category=category,
    )

    current_score = user["score"]
    decision = trust_engine.apply(current_score, severity)
    new_score = decision.new_score

    execute_db(
        "UPDATE users SET score = ? WHERE id = ?",
        (new_score, user["id"]),
    )
    execute_db(
        "INSERT INTO events (user_id, raw_input, delta) VALUES (?, ?, ?)",
        (user["id"], text, decision.delta),
    )

    action = decision.action

    tags = meta.get("tags", [])
    if "automation-tool" in tags or "automation-timing" in tags:

        if action.value < TrustAction.COOLDOWN.value:
            action = TrustAction.COOLDOWN

    if action == TrustAction.DELAY:
        time.sleep(5)

    if action == TrustAction.CAPTCHA:
        session["puzzle_required"] = True
        session["puzzle_correct_once"] = False
        flash(
            "Suspicious activity detected. CAPTCHA/puzzle verification required.",
            "warning",
        )
        return redirect(url_for("puzzle"))

    if action == TrustAction.COOLDOWN:
        cooldown_seconds = 5 
        session["cooldown_until"] = time.time() + cooldown_seconds
        flash(
            f"High suspicion: certain actions are temporarily disabled "
            f"(cooldown {cooldown_seconds} seconds).",
            "danger",
            )


    if action == TrustAction.TEMP_FREEZE:
        session.clear()
        flash(
            "Your account has been temporarily frozen due to very high-risk behavior.",
            "danger",
        )
        return redirect(url_for("login"))

    if action == TrustAction.PERM_BAN:
        session.clear()
        flash(
            "Your account has been banned due to critical behavior.",
            "danger",
        )
        return redirect(url_for("login"))


    flash(
        f"[Trust decision] Severity={severity.name}, "
        f"Δscore={decision.delta:+d}, New score={new_score}, "
        f"Reason={meta.get('reason', 'n/a')}, Tags={meta.get('tags', [])}",
        "info",
    )
    return redirect(url_for("dashboard"))



@app.route("/reset_score", methods=["POST"])
@login_required
def reset_score():
    user = g.user
    execute_db(
        "UPDATE users SET score = ? WHERE id = ?",
        (100, user["id"]),
    )
    execute_db(
        "INSERT INTO events (user_id, raw_input, delta) VALUES (?, ?, ?)",
        (user["id"], "[reset_score_100]", 0),
    )
    flash("Score reset to 100 (demo).", "success")
    return redirect(url_for("dashboard"))



@app.route("/reset_score_50", methods=["POST"])
@login_required
def reset_score_50():
    user = g.user
    execute_db(
        "UPDATE users SET score = ? WHERE id = ?",
        (50, user["id"]),
    )
    execute_db(
        "INSERT INTO events (user_id, raw_input, delta) VALUES (?, ?, ?)",
        (user["id"], "[reset_score_50]", 0),
    )
    flash("Score reset to 50 (demo).", "success")
    return redirect(url_for("dashboard"))



@app.route("/puzzle", methods=["GET", "POST"])
@login_required
def puzzle():
    import random

 
    if request.method == "GET" or "puzzle_answer" not in session:
        a, b, c = random.randint(1, 9), random.randint(1, 9), random.randint(1, 9)
        question = f"{a} + {b} × {c}"
        answer = a + b * c
        session["puzzle_question"] = question
        session["puzzle_answer"] = str(answer)
        return render_template("puzzle.html", question=question)


    user_answer = (request.form.get("answer") or "").strip()
    real_answer = session.get("puzzle_answer")
    correct_once = session.get("puzzle_correct_once", False)

    if user_answer == real_answer:
        if not correct_once:
      
            session["puzzle_correct_once"] = True
            flash("Incorrect answer, try again.", "danger")
        else:
        
            session.pop("puzzle_required", None)
            session.pop("puzzle_correct_once", None)
            session.pop("puzzle_answer", None)
            session.pop("puzzle_question", None)
            flash("Puzzle solved. You may continue.", "success")
            return redirect(url_for("dashboard"))
    else:
    
        session["puzzle_correct_once"] = False
        flash("Incorrect answer, try again.", "danger")


    a, b, c = random.randint(1, 9), random.randint(1, 9), random.randint(1, 9)
    question = f"{a} + {b} × {c}"
    answer = a + b * c
    session["puzzle_question"] = question
    session["puzzle_answer"] = str(answer)
    return render_template("puzzle.html", question=question)



@app.route("/admin/events")
@login_required
def admin_events():
    rows = query_db(
        """
        SELECT e.id,
               u.username,
               e.raw_input,
               e.delta,
               e.created_at
        FROM events e
        JOIN users u ON e.user_id = u.id
        ORDER BY e.id DESC
        LIMIT 200
        """
    )
    return render_template("admin_events.html", rows=rows)



if __name__ == "__main__":
 
    try:
        with app.app_context():
            query_db("SELECT 1 FROM users LIMIT 1")
    except Exception:
        with app.app_context():
            print("Initializing DB...")
            init_db()

    app.run(debug=True, host="127.0.0.1", port=5000)

