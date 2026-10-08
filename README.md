# Authenticator 2FA Login

A Flask application for username/password login with Google Authenticator and Microsoft Authenticator support.

## Features
- Username and password login
- Google/Microsoft Authenticator TOTP login
- Account expiry date
- Location ID field
- Active/inactive flag
- Login timestamp
- Password reset

## Setup

```bash
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

## Database
The SQLite database is created automatically at `auth.db`.

## Notes
- The QR code is saved in `static/qr_codes`.
- TOTP secrets are stored in the `users` table.
- Passwords are hashed using Werkzeug.
