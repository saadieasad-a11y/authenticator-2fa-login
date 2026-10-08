from flask import Flask, render_template, request, redirect, url_for, session, flash
import pyotp
import qrcode
import os
import secrets
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/auth_app")
QR_DIR = os.path.join(BASE_DIR, "static", "qr_codes")
os.makedirs(QR_DIR, exist_ok=True)


def get_db_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def init_db():
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                account_expirydate DATE,
                location_id VARCHAR(255) NOT NULL,
                active_flag BOOLEAN NOT NULL DEFAULT TRUE,
                logintime TIMESTAMP,
                totp_secret TEXT,
                is_2fa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.commit()
    conn.close()


def get_user_by_username(username):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return user


def update_login_time(username):
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE users SET logintime = %s WHERE username = %s",
            (datetime.now(), username),
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


def normalize_account_expiry(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, str):
        return datetime.strptime(value, "%Y-%m-%d").date()
    return value


@app.before_request
def ensure_db():
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
        account_expirydate = request.form.get("account_expirydate", "") or None
        active_flag = True if request.form.get("active_flag") == "on" else False
        enable_2fa = True if request.form.get("enable_2fa") == "on" else False

        if not username or not password or not location_id:
            flash("Username, password and location_id are required.", "danger")
            return redirect(url_for("register"))

        if get_user_by_username(username):
            flash("Username already exists.", "danger")
            return redirect(url_for("register"))

        secret = pyotp.random_base32() if enable_2fa else None
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users
                (username, password_hash, account_expirydate, location_id, active_flag, is_2fa_enabled, totp_secret)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (username, hashed_password, account_expirydate, location_id, active_flag, enable_2fa, secret),
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

        expiry_date = normalize_account_expiry(user.get("account_expirydate"))
        if expiry_date is not None and datetime.now().date() > expiry_date:
            flash("Your account has expired.", "danger")
            return render_template("login.html", username=username)

        if user.get("active_flag") is not True and user.get("active_flag") != 1:
            flash("Your account is inactive.", "danger")
            return render_template("login.html", username=username)

        if user.get("is_2fa_enabled") in (True, 1):
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
        "account_expirydate": normalize_account_expiry(user.get("account_expirydate")),
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
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET password_hash = %s WHERE username = %s",
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
