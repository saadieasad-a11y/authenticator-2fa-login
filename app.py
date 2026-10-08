from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import pyotp
import qrcode
import os
import secrets
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "auth.db")
QR_DIR = os.path.join(BASE_DIR, "static", "qr_codes")

os.makedirs(QR_DIR, exist_ok=True)


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    schema_path = os.path.join(BASE_DIR, "database", "schema.sql")
    if not os.path.exists(schema_path):
        os.makedirs(os.path.dirname(schema_path), exist_ok=True)
        with open(schema_path, "w", encoding="utf-8") as f:
            f.write('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    account_expirydate TEXT,
    location_id TEXT NOT NULL,
    active_flag INTEGER NOT NULL DEFAULT 1,
    logintime TEXT,
    totp_secret TEXT,
    is_2fa_enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
''')

    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(schema_sql)


def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return user


def update_login_time(username):
    conn = get_db_connection()
    conn.execute(
        "UPDATE users SET logintime = ? WHERE username = ?",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username),
    )
    conn.commit()
    conn.close()


def generate_qr_code(username, secret):
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="MySecureApp",
    )
    image_path = os.path.join(QR_DIR, f"{username}_qr.png")
    qrcode.make(uri).save(image_path)
    return f"/static/qr_codes/{username}_qr.png"


@app.before_request
def ensure_db():
    if not os.path.exists(DB_PATH):
        init_db()


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        location_id = request.form.get("location_id", "").strip()
        account_expirydate = request.form.get("account_expirydate", "")
        active_flag = 1 if request.form.get("active_flag") == "on" else 0
        enable_2fa = 1 if request.form.get("enable_2fa") == "on" else 0

        if not username or not password or not location_id:
            flash("Username, password and location_id are required.", "danger")
            return redirect(url_for("register"))

        if get_user_by_username(username):
            flash("Username already exists.", "danger")
            return redirect(url_for("register"))

        secret = pyotp.random_base32() if enable_2fa else None
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        conn.execute(
            """
            INSERT INTO users
            (username, password_hash, account_expirydate, location_id, active_flag, is_2fa_enabled, totp_secret)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (username, hashed_password, account_expirydate or None, location_id, active_flag, enable_2fa, secret),
        )
        conn.commit()
        conn.close()

        if enable_2fa:
            qr_path = generate_qr_code(username, secret)
            flash("Registration successful. Scan the QR with Google or Microsoft Authenticator.", "success")
            return render_template("login.html", qr_path=qr_path, username=username, show_2fa_setup=True)

        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    qr_path = request.args.get("qr_path")
    username = request.args.get("username") or request.form.get("username", "")
    require_totp = False

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        totp_code = request.form.get("totp_code", "").strip()

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("login.html", username=username)

        user = get_user_by_username(username)
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.", "danger")
            return render_template("login.html", username=username)

        if user["account_expirydate"]:
            try:
                expiry = datetime.strptime(user["account_expirydate"], "%Y-%m-%d")
                if datetime.now().date() > expiry.date():
                    flash("Your account has expired.", "danger")
                    return render_template("login.html", username=username)
            except ValueError:
                pass

        if user["active_flag"] != 1:
            flash("Your account is inactive.", "danger")
            return render_template("login.html", username=username)

        if user["is_2fa_enabled"] == 1:
            if not totp_code:
                require_totp = True
                return render_template("login.html", username=username, require_totp=True)

            totp = pyotp.TOTP(user["totp_secret"])
            if not totp.verify(totp_code, valid_window=1):
                flash("Invalid authenticator code.", "danger")
                return render_template("login.html", username=username, require_totp=True)

        session["username"] = username
        update_login_time(username)
        flash("Login successful!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html", username=username, qr_path=qr_path, require_totp=require_totp)


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    user = get_user_by_username(session["username"])
    if not user:
        session.clear()
        return redirect(url_for("login"))

    user_data = {
        "username": user["username"],
        "location_id": user["location_id"],
        "account_expirydate": user["account_expirydate"],
        "active_flag": bool(user["active_flag"]),
        "logintime": user["logintime"],
        "two_factor_enabled": bool(user["is_2fa_enabled"]),
    }
    return render_template("dashboard.html", user=user_data)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        new_password = request.form.get("new_password", "")

        if not username or not new_password:
            flash("Username and new password are required.", "danger")
            return redirect(url_for("reset_password"))

        user = get_user_by_username(username)
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("reset_password"))

        conn = get_db_connection()
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (generate_password_hash(new_password), username),
        )
        conn.commit()
        conn.close()

        flash("Password reset successful. Please log in again.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)

