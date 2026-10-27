# KP4000 Secure API

Starter implementation for the KP4000 B4A client and PHP + SQLite API.

## Files

- `api/config.php`: non-secret configuration and database path.
- `api/common.php`: JSON responses, request validation, PDO SQLite connection.
- `api/register-device.php`: one-time activation-code registration of a device public key.
- `api/start.php`: issues a short-lived challenge to an active device.
- `api/verify-device.php`: verifies a one-time signature and returns a bearer token.
- `database/schema.sql`: schema for a new/test database; not a migration for an existing production database.

## Endpoint flow

1. `POST api/register-device.php` with `device_id`, PEM `public_key`, and a 32-character hexadecimal `activation_code`.
2. `POST api/start.php` with `device_id`; receives `challenge_id` and `challenge`.
3. Sign the exact UTF-8 string `challenge_id.challenge` using the device private key and SHA-256. Send the Base64 signature to `POST api/verify-device.php` with `device_id` and `challenge_id`.
4. On successful verification, the API returns a random bearer token once. Only its SHA-256 hash is stored in SQLite.

Activation codes are provisioned by storing `SHA-256(uppercase_activation_code)` in `device_activation_codes.activation_code_hash`. Do not store or commit plaintext activation codes.

## Configuration

The database path is read from `KP4000_DB_PATH`. If unset, the default is `/home/helpscho/mydatabase/myfile.sqlite`. Configure environment variables through the hosting control panel where possible. The database must be outside the public web root, readable/writable only by the required server account, and backed up before schema changes.

## Important deployment warning

This repository is a starter and has **not** been deployed or tested on the hosting account. The schema is for a new/test database. The existing production SQLite database has its own tables and must be inspected and reconciled before using these queries. Do not run `database/schema.sql` against the live database blindly.

Before production:
- Confirm the B4A key algorithm and signature format match PHP OpenSSL verification.
- Ensure HTTPS is enforced.
- Add rate limiting, request logging without secrets, and a token-authentication middleware for protected endpoints.
- Test against a disposable database and verify expiry, replay rejection, activation-code reuse rejection, and concurrent requests.
- Keep private keys, passwords, API tokens, and real activation codes out of Git.
