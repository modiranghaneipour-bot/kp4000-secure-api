-- Initial schema for the repository starter only.
-- BACK UP the live database and reconcile its schema before applying anywhere.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'active', 'disabled', 'revoked')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Store only SHA-256 hashes of one-time activation codes.
-- Provision activation_code_hash = SHA-256(uppercase 32-character hex code).
CREATE TABLE IF NOT EXISTS device_activation_codes (
    activation_code_hash TEXT PRIMARY KEY,
    expires_at INTEGER NULL,
    used_at INTEGER NULL,
    bound_device_id TEXT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (bound_device_id) REFERENCES devices(device_id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS api_challenges (
    challenge_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    challenge_value TEXT NOT NULL,
    challenge_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_api_challenges_device_expiry
    ON api_challenges(device_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_api_challenges_expiry
    ON api_challenges(expires_at);

CREATE TABLE IF NOT EXISTS api_tokens (
    token_hash TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_device_expiry
    ON api_tokens(device_id, expires_at);
