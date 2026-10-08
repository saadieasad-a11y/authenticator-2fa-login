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
