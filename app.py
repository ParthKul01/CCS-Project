"""
MFA Login System - password (bcrypt) + TOTP (RFC 6238) using Flask.

Flow:
  Register -> Set up authenticator (scan QR, confirm code) -> Dashboard
  Login    -> Password check -> TOTP check -> Dashboard
"""
import base64
import hmac
import io
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import pyotp
import qrcode
from flask import (Flask, flash, g, redirect, render_template, request,
                   session, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFError, CSRFProtect

APP_NAME = "CCS MFA Login System"
TOTP_INTERVAL = 30          # seconds per code (RFC 6238 default)
TOTP_WINDOW = 1             # accept +/- 1 step to allow clock drift
MAX_FAILED_ATTEMPTS = 5     # failures before the account is locked
LOCKOUT_SECONDS = 300       # lock duration (5 minutes)
PRE_AUTH_TTL = 300          # seconds allowed between password and OTP step
SETUP_TTL = 600             # seconds allowed to finish MFA enrolment

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
GENERIC_LOGIN_ERROR = "Invalid username or password."

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash    BLOB    NOT NULL,
    totp_secret      TEXT,
    mfa_enabled      INTEGER NOT NULL DEFAULT 0,
    failed_attempts  INTEGER NOT NULL DEFAULT 0,
    locked_until     INTEGER NOT NULL DEFAULT 0,
    last_totp_step   INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER,
    username    TEXT,
    event       TEXT    NOT NULL,
    ip          TEXT,
    created_at  INTEGER NOT NULL
);
"""

# Used to keep response time similar when the username does not exist.
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt(rounds=4))


# --------------------------------------------------------------------------
# Helper functions (no Flask state needed)
# --------------------------------------------------------------------------
def validate_username(username):
    if not USERNAME_RE.match(username):
        return ["Username must be 3-20 characters: letters, numbers, underscore."]
    return []


def validate_password(password):
    errors = []
    if len(password) < 8 or len(password) > 64:
        errors.append("Password must be 8-64 characters long.")
    if len(password.encode("utf-8")) > 72:  # bcrypt input limit
        errors.append("Password is too long (max 72 bytes).")
    if not re.search(r"[a-z]", password):
        errors.append("Password needs a lowercase letter.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password needs an uppercase letter.")
    if not re.search(r"\d", password):
        errors.append("Password needs a digit.")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("Password needs a special character.")
    return errors


def check_password(password, hashed):
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed)
    except ValueError:
        return False


def verify_totp(secret, code, last_used_step):
    """
    Return the matching time step if `code` is valid, else None.
    Steps <= last_used_step are rejected so a code cannot be replayed.
    """
    if not re.fullmatch(r"\d{6}", code or ""):
        return None
    totp = pyotp.TOTP(secret, interval=TOTP_INTERVAL)
    current = int(time.time() // TOTP_INTERVAL)
    for step in range(current - TOTP_WINDOW, current + TOTP_WINDOW + 1):
        if step <= last_used_step:
            continue
        if hmac.compare_digest(totp.generate_otp(step), code):
            return step
    return None


def make_qr_data_uri(uri):
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def load_secret_key(app):
    """SECRET_KEY from env, else generate once and keep in instance/."""
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    path = os.path.join(app.instance_path, "secret_key")
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(path, "w") as f:
        f.write(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


# --------------------------------------------------------------------------
# Application factory
# --------------------------------------------------------------------------
def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)

    app.config.update(
        DATABASE=os.path.join(app.instance_path, "mfa.db"),
        BCRYPT_ROUNDS=12,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        RATELIMIT_STORAGE_URI="memory://",
    )
    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = load_secret_key(app)

    CSRFProtect(app)
    limiter = Limiter(key_func=get_remote_address, app=app)
    app.limiter = limiter  # keep a strong reference (Flask-Limiter uses weakrefs)

    # ---------------- database ----------------
    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(exc=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    with app.app_context():
        get_db().executescript(SCHEMA)
        get_db().commit()

    # ---------------- small helpers ----------------
    def now():
        return int(time.time())

    def get_user_by_id(user_id):
        return get_db().execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    def get_user_by_username(username):
        return get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    def log_event(event, user=None, username=None):
        db = get_db()
        db.execute(
            "INSERT INTO events (user_id, username, event, ip, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (user["id"] if user else None,
             user["username"] if user else (username or "")[:30],
             event, request.remote_addr, now()))
        db.commit()

    def is_locked(user):
        return user["locked_until"] > now()

    def lock_message(user):
        minutes = max(1, (user["locked_until"] - now() + 59) // 60)
        return f"Account locked after too many failed attempts. Try again in {minutes} minute(s)."

    def register_failure(user):
        attempts = user["failed_attempts"] + 1
        locked_until = 0
        if attempts >= MAX_FAILED_ATTEMPTS:
            locked_until = now() + LOCKOUT_SECONDS
            attempts = 0
            log_event("account_locked", user)
        db = get_db()
        db.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
            (attempts, locked_until, user["id"]))
        db.commit()

    def current_user():
        user_id = session.get("user_id")
        return get_user_by_id(user_id) if user_id else None

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if user is None:
                if "user_id" in session:  # stale session, e.g. deleted user
                    session.clear()
                flash("Please log in to continue.", "error")
                return redirect(url_for("login"))
            g.user = user
            return view(*args, **kwargs)
        return wrapped

    def pre_auth_user():
        """User who passed the password step but not OTP yet."""
        user_id = session.get("pre_auth_user_id")
        started = session.get("pre_auth_time", 0)
        if not user_id or now() - started > PRE_AUTH_TTL:
            return None
        user = get_user_by_id(user_id)
        if user is None or not user["mfa_enabled"]:
            return None
        return user

    def setup_user():
        """User who is allowed to enrol an authenticator app."""
        user_id = session.get("setup_user_id")
        started = session.get("setup_time", 0)
        if not user_id or now() - started > SETUP_TTL:
            return None
        user = get_user_by_id(user_id)
        if user is None or user["mfa_enabled"]:
            return None
        return user

    def start_session(user):
        session.clear()
        session.permanent = True
        session["user_id"] = user["id"]
        session["login_time"] = now()

    # ---------------- template helpers ----------------
    @app.template_filter("datetimefmt")
    def datetimefmt(ts):
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC")

    @app.context_processor
    def inject_globals():
        return {"app_name": APP_NAME, "logged_in": "user_id" in session}

    @app.after_request
    def set_security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "form-action 'self'; frame-ancestors 'none'")
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ---------------- routes ----------------
    @app.route("/")
    def index():
        return redirect(url_for("dashboard" if current_user() else "login"))

    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("10 per minute", methods=["POST"])
    def register():
        if current_user():
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm", "")

            errors = validate_username(username) + validate_password(password)
            if password != confirm:
                errors.append("Passwords do not match.")
            if errors:
                for e in errors:
                    flash(e, "error")
                return render_template("register.html", username=username), 400

            hashed = bcrypt.hashpw(
                password.encode("utf-8"),
                bcrypt.gensalt(rounds=app.config["BCRYPT_ROUNDS"]))
            db = get_db()
            try:
                cur = db.execute(
                    "INSERT INTO users (username, password_hash, created_at) "
                    "VALUES (?, ?, ?)", (username, hashed, now()))
                db.commit()
            except sqlite3.IntegrityError:
                flash("That username is already taken.", "error")
                return render_template("register.html", username=username), 409

            user = get_user_by_id(cur.lastrowid)
            log_event("registered", user)
            session.clear()
            session["setup_user_id"] = user["id"]
            session["setup_time"] = now()
            flash("Account created. Set up your authenticator app.", "info")
            return redirect(url_for("setup_mfa"))
        return render_template("register.html", username="")

    @app.route("/setup-mfa", methods=["GET", "POST"])
    @limiter.limit("10 per minute", methods=["POST"])
    def setup_mfa():
        user = setup_user()
        if user is None:
            flash("Log in to continue MFA setup.", "error")
            return redirect(url_for("login"))

        secret = session.get("pending_secret")
        if not secret:
            secret = pyotp.random_base32()
            session["pending_secret"] = secret

        if request.method == "POST":
            if is_locked(user):
                flash(lock_message(user), "error")
            else:
                code = request.form.get("otp", "").replace(" ", "")
                step = verify_totp(secret, code, 0)
                if step is None:
                    register_failure(user)
                    log_event("mfa_setup_failed", user)
                    flash("Invalid code. Check your app and try again.", "error")
                else:
                    db = get_db()
                    db.execute(
                        "UPDATE users SET totp_secret = ?, mfa_enabled = 1, "
                        "last_totp_step = ?, failed_attempts = 0, locked_until = 0 "
                        "WHERE id = ?", (secret, step, user["id"]))
                    db.commit()
                    log_event("mfa_enabled", user)
                    start_session(user)
                    log_event("login_success", user)
                    flash("MFA is enabled. You are logged in.", "info")
                    return redirect(url_for("dashboard"))

        uri = pyotp.TOTP(secret, interval=TOTP_INTERVAL).provisioning_uri(
            name=user["username"], issuer_name=APP_NAME)
        return render_template("setup_mfa.html",
                               qr=make_qr_data_uri(uri), secret=secret)

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("10 per minute", methods=["POST"])
    def login():
        if current_user():
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = get_user_by_username(username)

            if user is None:
                check_password(password, _DUMMY_HASH)  # equalise timing
                log_event("login_failed_unknown_user", username=username)
                flash(GENERIC_LOGIN_ERROR, "error")
                return render_template("login.html"), 401

            if is_locked(user):
                log_event("login_blocked_locked", user)
                flash(lock_message(user), "error")
                return render_template("login.html"), 403

            if not check_password(password, user["password_hash"]):
                register_failure(user)
                log_event("login_failed_password", user)
                flash(GENERIC_LOGIN_ERROR, "error")
                return render_template("login.html"), 401

            # Password is correct.
            session.clear()
            if not user["mfa_enabled"]:
                session["setup_user_id"] = user["id"]
                session["setup_time"] = now()
                flash("Finish MFA setup to continue.", "info")
                return redirect(url_for("setup_mfa"))

            session["pre_auth_user_id"] = user["id"]
            session["pre_auth_time"] = now()
            log_event("password_verified", user)
            return redirect(url_for("verify_otp"))
        return render_template("login.html")

    @app.route("/verify-otp", methods=["GET", "POST"])
    @limiter.limit("10 per minute", methods=["POST"])
    def verify_otp():
        user = pre_auth_user()
        if user is None:
            session.clear()
            flash("Log in with your password first.", "error")
            return redirect(url_for("login"))

        if request.method == "POST":
            if is_locked(user):
                session.clear()
                flash(lock_message(user), "error")
                return redirect(url_for("login"))

            code = request.form.get("otp", "").replace(" ", "")
            step = verify_totp(user["totp_secret"], code, user["last_totp_step"])
            ok = False
            if step is not None:
                # Conditional update makes the replay check atomic.
                db = get_db()
                cur = db.execute(
                    "UPDATE users SET last_totp_step = ?, failed_attempts = 0, "
                    "locked_until = 0 WHERE id = ? AND last_totp_step < ?",
                    (step, user["id"], step))
                db.commit()
                ok = cur.rowcount == 1

            if not ok:
                register_failure(user)
                log_event("otp_failed", user)
                flash("Invalid or expired code.", "error")
                return render_template("verify_otp.html"), 401

            start_session(user)
            log_event("login_success", user)
            return redirect(url_for("dashboard"))
        return render_template("verify_otp.html")

    @app.route("/dashboard")
    @login_required
    def dashboard():
        events = get_db().execute(
            "SELECT event, ip, created_at FROM events WHERE user_id = ? "
            "ORDER BY id DESC LIMIT 10", (g.user["id"],)).fetchall()
        return render_template("dashboard.html", user=g.user, events=events)

    @app.route("/logout", methods=["POST"])
    def logout():
        user = current_user()
        if user:
            log_event("logout", user)
        session.clear()
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))

    # ---------------- error pages ----------------
    @app.errorhandler(CSRFError)
    def handle_csrf(e):
        return render_template(
            "error.html", title="Form expired",
            message="Your form session expired. Go back and try again."), 400

    @app.errorhandler(404)
    def handle_404(e):
        return render_template(
            "error.html", title="Page not found",
            message="That page does not exist."), 404

    @app.errorhandler(429)
    def handle_429(e):
        return render_template(
            "error.html", title="Too many requests",
            message="Slow down and try again in a minute."), 429

    return app


if __name__ == "__main__":
    create_app().run(
        host="127.0.0.1", port=5000,
        debug=os.environ.get("FLASK_DEBUG") == "1")
