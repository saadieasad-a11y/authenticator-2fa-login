CREATE TABLE IF NOT EXISTS users (
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
