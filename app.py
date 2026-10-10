from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import pyotp
import qrcode
import os
import secrets
import io
import base64
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from functools import wraps
import json
import re

load_dotenv()

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@192.168.56.101:5432/auth_app")
QR_DIR = os.path.join(BASE_DIR, "static", "qr_codes")
os.makedirs(QR_DIR, exist_ok=True)

CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
}


def get_db_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def validate_phone_number(phone):
    """Validate phone number (basic validation: 10+ digits)"""
    phone_clean = re.sub(r'\D', '', phone)
    return len(phone_clean) >= 10


def init_db():
    conn = get_db_connection()
    with conn.cursor() as cur:
        # Create roles table
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS roles (
                id SERIAL PRIMARY KEY,
                role_name VARCHAR(100) UNIQUE NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

        # Create users table with mobile_no
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                mobile_no VARCHAR(20) NOT NULL,
                account_expirydate DATE,
                location_id VARCHAR(255) NOT NULL,
                active_flag BOOLEAN NOT NULL DEFAULT TRUE,
                logintime TIMESTAMP,
                totp_secret TEXT,
                is_2fa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                qr_scanned BOOLEAN NOT NULL DEFAULT FALSE,
                role_id INTEGER REFERENCES roles(id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

        # Insert default roles if they don't exist
        cur.execute("SELECT COUNT(*) as count FROM roles;")
        if cur.fetchone()['count'] == 0:
            cur.execute(
                """
                INSERT INTO roles (role_name, description) VALUES
                ('admin', 'Administrator with full access'),
                ('user', 'Regular user'),
                ('manager', 'Manager with limited access');
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


def generate_qr_code_base64(username, secret):
    """Generate QR code as base64 string"""
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="MySecureApp",
    )
    qr = qrcode.QRCode()
    qr.add_data(uri)
    qr.make()
    
    img = qr.make_image()
    
    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    img_str = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_str}"


@app.before_request
def ensure_db():
    init_db()


@app.after_request
def set_cors_headers(response):
    for key, value in CORS_HEADERS.items():
        response.headers[key] = value
    return response


# ==================== API ROUTES ====================

@app.route('/api/auth/register', methods=['POST', 'OPTIONS'])
def api_register():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    mobile_no = data.get('mobile_no', '').strip()
    location_id = data.get('location_id', '').strip()
    role_id = data.get('role_id', 2)  # Default to 'user' role
    account_expirydate = data.get('account_expirydate')

    # Validation
    if not username or not password or not mobile_no or not location_id:
        return jsonify({'success': False, 'message': 'Username, password, mobile number and location_id are required.'}), 400

    if not validate_phone_number(mobile_no):
        return jsonify({'success': False, 'message': 'Mobile number must have at least 10 digits.'}), 400

    if len(password) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters long.'}), 400

    if get_user_by_username(username):
        return jsonify({'success': False, 'message': 'Username already exists.'}), 400

    hashed_password = generate_password_hash(password)

    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users
                (username, password_hash, mobile_no, account_expirydate, location_id, active_flag, role_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (username, hashed_password, mobile_no, account_expirydate, location_id, True, role_id),
            )
            user_id = cur.fetchone()['id']
            conn.commit()

        return jsonify({
            'success': True,
            'message': 'Registration successful! Please log in.',
            'user_id': user_id,
            'username': username
        }), 201
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        conn.close()


@app.route('/api/auth/login', methods=['POST', 'OPTIONS'])
def api_login():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password are required.'}), 400

    user = get_user_by_username(username)
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'success': False, 'message': 'Invalid username or password.'}), 401

    if user['account_expirydate']:
        try:
            expiry = datetime.strptime(str(user['account_expirydate']), '%Y-%m-%d').date()
            if datetime.now().date() > expiry:
                return jsonify({'success': False, 'message': 'Your account has expired.'}), 401
        except ValueError:
            pass

    if not user['active_flag']:
        return jsonify({'success': False, 'message': 'Your account is inactive.'}), 401

    # If 2FA not enabled yet, show QR code for setup
    if not user['is_2fa_enabled']:
        secret = pyotp.random_base32()
        qr_code_base64 = generate_qr_code_base64(username, secret)

        # Save secret temporarily
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET totp_secret = %s WHERE username = %s",
                (secret, username),
            )
            conn.commit()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Please set up 2FA',
            'setup_2fa': True,
            'qr_code': qr_code_base64,
            'username': username
        }), 200

    # If 2FA enabled, require authenticator code
    if user['is_2fa_enabled'] and user['qr_scanned']:
        return jsonify({
            'success': True,
            'message': 'Password verified. Please enter authenticator code.',
            'require_totp': True,
            'username': username
        }), 200

    return jsonify({'success': False, 'message': 'Please complete 2FA setup.'}), 401


@app.route('/api/auth/verify-2fa', methods=['POST', 'OPTIONS'])
def api_verify_2fa():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json()
    username = data.get('username', '').strip()
    totp_code = data.get('totp_code', '').strip()

    if not username or not totp_code:
        return jsonify({'success': False, 'message': 'Username and authenticator code are required.'}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404

    if not user['totp_secret']:
        return jsonify({'success': False, 'message': 'No 2FA secret found. Please try logging in again.'}), 400

    totp = pyotp.TOTP(user['totp_secret'])
    if not totp.verify(totp_code, valid_window=1):
        return jsonify({'success': False, 'message': 'Invalid authenticator code.'}), 401

    # Mark 2FA as enabled and QR as scanned (first time setup)
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE users SET is_2fa_enabled = TRUE, qr_scanned = TRUE, logintime = %s WHERE username = %s",
            (datetime.now(), username),
        )
        conn.commit()
    conn.close()

    # Get user details for response
    user = get_user_by_username(username)

    return jsonify({
        'success': True,
        'message': 'Login successful!',
        'user': {
            'id': user['id'],
            'username': user['username'],
            'mobile_no': user['mobile_no'],
            'location_id': user['location_id'],
            'role_id': user['role_id'],
            'account_expirydate': str(user['account_expirydate']) if user['account_expirydate'] else None,
            'active_flag': user['active_flag'],
            'logintime': user['logintime'].isoformat() if user['logintime'] else None,
            'two_factor_enabled': user['is_2fa_enabled']
        }
    }), 200


@app.route('/api/auth/verify-totp', methods=['POST', 'OPTIONS'])
def api_verify_totp():
    """Verify TOTP code on subsequent logins (after 2FA is already set up)"""
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json()
    username = data.get('username', '').strip()
    totp_code = data.get('totp_code', '').strip()

    if not username or not totp_code:
        return jsonify({'success': False, 'message': 'Username and authenticator code are required.'}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404

    totp = pyotp.TOTP(user['totp_secret'])
    if not totp.verify(totp_code, valid_window=1):
        return jsonify({'success': False, 'message': 'Invalid authenticator code.'}), 401

    update_login_time(username)

    return jsonify({
        'success': True,
        'message': 'Login successful!',
        'user': {
            'id': user['id'],
            'username': user['username'],
            'mobile_no': user['mobile_no'],
            'location_id': user['location_id'],
            'role_id': user['role_id'],
            'account_expirydate': str(user['account_expirydate']) if user['account_expirydate'] else None,
            'active_flag': user['active_flag'],
            'logintime': user['logintime'].isoformat() if user['logintime'] else None,
            'two_factor_enabled': user['is_2fa_enabled']
        }
    }), 200


@app.route('/api/auth/reset-password', methods=['POST', 'OPTIONS'])
def api_reset_password():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    data = request.get_json()
    username = data.get('username', '').strip()
    new_password = data.get('new_password', '')

    if not username or not new_password:
        return jsonify({'success': False, 'message': 'Username and new password are required.'}), 400

    if len(new_password) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters long.'}), 400

    user = get_user_by_username(username)
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404

    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE users SET password_hash = %s, updated_at = %s WHERE username = %s",
            (generate_password_hash(new_password), datetime.now(), username),
        )
        conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'Password reset successful.'}), 200


@app.route('/api/auth/user/<username>', methods=['GET', 'OPTIONS'])
def api_get_user(username):
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    user = get_user_by_username(username)
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404

    return jsonify({
        'success': True,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'mobile_no': user['mobile_no'],
            'location_id': user['location_id'],
            'role_id': user['role_id'],
            'account_expirydate': str(user['account_expirydate']) if user['account_expirydate'] else None,
            'active_flag': user['active_flag'],
            'logintime': user['logintime'].isoformat() if user['logintime'] else None,
            'two_factor_enabled': user['is_2fa_enabled'],
            'qr_scanned': user['qr_scanned']
        }
    }), 200


@app.route('/api/roles', methods=['GET', 'OPTIONS'])
def api_get_roles():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT id, role_name, description FROM roles ORDER BY id;")
        roles = cur.fetchall()
    conn.close()

    return jsonify({
        'success': True,
        'roles': [dict(role) for role in roles]
    }), 200


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
