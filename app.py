from flask import Flask, request, render_template, redirect, url_for, session, flash
import sqlite3
import bcrypt
import pyotp
import time
import os

app = Flask(__name__)
app.secret_key = "dev-secret-key-change-me"

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 900  # 15 minutes


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            totp_secret TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            locked_until REAL DEFAULT 0
        )
        """
    )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        conn = get_db()
        existing = conn.execute(
            "SELECT 1 FROM users WHERE username=?", (username,)
        ).fetchone()
        if existing:
            conn.close()
            flash("Username already exists.")
            return redirect(url_for("register"))
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
        totp_secret = pyotp.random_base32()
        conn.execute(
            "INSERT INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?)",
            (username, pw_hash, totp_secret),
        )
        conn.commit()
        conn.close()
        return render_template("registered.html", username=username, secret=totp_secret)
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()

        if user is None:
            conn.close()
            flash("Invalid username or password.")
            return redirect(url_for("login"))

        if user["locked_until"] and user["locked_until"] > time.time():
            remaining = int(user["locked_until"] - time.time())
            conn.close()
            flash(f"Account locked. Try again in {remaining} seconds.")
            return redirect(url_for("login"))

        if bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            conn.execute(
                "UPDATE users SET failed_attempts=0, locked_until=0 WHERE username=?",
                (username,),
            )
            conn.commit()
            conn.close()
            session["pending_user"] = username
            return redirect(url_for("otp"))
        else:
            attempts = user["failed_attempts"] + 1
            locked_until = 0
            if attempts >= MAX_ATTEMPTS:
                locked_until = time.time() + LOCKOUT_SECONDS
            conn.execute(
                "UPDATE users SET failed_attempts=?, locked_until=? WHERE username=?",
                (attempts, locked_until, username),
            )
            conn.commit()
            conn.close()
            if locked_until:
                flash(
                    f"Too many failed attempts. Account locked for {LOCKOUT_SECONDS // 60} minutes."
                )
            else:
                flash(f"Invalid username or password. Attempt {attempts}/{MAX_ATTEMPTS}.")
            return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/otp", methods=["GET", "POST"])
def otp():
    username = session.get("pending_user")
    if not username:
        return redirect(url_for("login"))
    if request.method == "POST":
        code = request.form["code"].strip()
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()
        conn.close()
        totp = pyotp.TOTP(user["totp_secret"])
        if totp.verify(code, valid_window=1):
            session.pop("pending_user", None)
            session["user"] = username
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid or expired OTP code.")
            return redirect(url_for("otp"))
    return render_template("otp.html", username=username)


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["user"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
