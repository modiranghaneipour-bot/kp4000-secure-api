# KP4000 Secure API

Starter repository for the KP4000 B4A client and PHP + SQLite API.

## Current scope

- PHP JSON response helpers and PDO/SQLite connection.
- Device challenge endpoint (`api/start.php`).
- Signature verification endpoint (`api/verify-device.php`).
- SQL migration notes.
- No production secrets are committed.

## Important

This is a starter implementation, not a claim that the API has been deployed or tested on the hosting account. Before deployment, verify the live database schema, PHP/OpenSSL availability, permissions, and the B4A signing format.

The server database path is configurable with `KP4000_DB_PATH`. The default in this starter is `/home/helpscho/mydatabase/myfile.sqlite`; change it if the actual server database is elsewhere. Never commit private keys, passwords, API tokens, or real activation codes.

## Endpoints

- `POST api/start.php`: JSON `{"device_id":"..."}`; returns a short-lived challenge for an active, registered device.
- `POST api/verify-device.php`: JSON `{"device_id":"...","challenge_id":"...","signature":"..."}`; verifies a one-time signature and returns a bearer token once.

The signature message is exactly `challenge_id.challenge` (UTF-8), signed with the device private key using SHA-256. The signature sent by the client is Base64-encoded. The public key in `devices.public_key` must be a PEM public key accepted by OpenSSL.

## Deployment checklist

1. Confirm the existing SQLite schema matches the queries in these files.
2. Keep the database outside the public web root.
3. Configure `KP4000_DB_PATH` as a server environment variable when possible.
4. Ensure HTTPS is enforced by the web server.
5. Run tests against a non-production database first.
6. Add rate limiting and operational monitoring at the web server/API gateway before production use.
