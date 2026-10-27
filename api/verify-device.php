<?php
declare(strict_types=1);

require_once __DIR__ . '/common.php';

api_require_post();
$data = api_read_json();
$deviceId = api_string($data, 'device_id', 128);
$challengeId = api_string($data, 'challenge_id', 64);
$signatureB64 = api_string($data, 'signature', 8192);
$signature = base64_decode($signatureB64, true);
if ($signature === false || $signature === '') {
    api_json(400, ['ok' => false, 'error' => 'invalid_signature_encoding']);
}

try {
    $db = api_db();
    $db->beginTransaction();

    $stmt = $db->prepare(
        "SELECT d.public_key, c.challenge_hash, c.expires_at, c.used_at
         FROM devices d
         JOIN api_challenges c ON c.device_id = d.device_id
         WHERE d.device_id = :device_id
           AND d.status = 'active'
           AND c.challenge_id = :challenge_id
         LIMIT 1"
    );
    $stmt->execute([':device_id' => $deviceId, ':challenge_id' => $challengeId]);
    $row = $stmt->fetch();

    if (!$row || $row['used_at'] !== null || (int)$row['expires_at'] < time()) {
        $db->rollBack();
        api_json(401, ['ok' => false, 'error' => 'challenge_invalid_or_expired']);
    }

    // The client signs exactly: challenge_id.challenge (UTF-8), using SHA-256.
    // Challenge value is stored hashed; the value received at start is used by the client.
    // Reconstructing it from the stored hash is impossible, so compare against a signed
    // message that includes the server-held challenge value in the next schema revision.
    // This endpoint expects challenge_value to be stored by the migration below.
    $challengeLookup = $db->prepare(
        'SELECT challenge_value FROM api_challenges WHERE challenge_id = :id LIMIT 1'
    );
    $challengeLookup->execute([':id' => $challengeId]);
    $challengeValue = $challengeLookup->fetchColumn();
    if (!is_string($challengeValue) || $challengeValue === '') {
        $db->rollBack();
        api_json(500, ['ok' => false, 'error' => 'challenge_schema_mismatch']);
    }

    $message = $challengeId . '.' . $challengeValue;
    $publicKey = openssl_pkey_get_public((string)$row['public_key']);
    if ($publicKey === false) {
        $db->rollBack();
        error_log('KP4000 invalid stored public key for device ' . $deviceId);
        api_json(500, ['ok' => false, 'error' => 'device_key_invalid']);
    }
    $verified = openssl_verify($message, $signature, $publicKey, OPENSSL_ALGO_SHA256);
    openssl_free_key($publicKey);
    if ($verified !== 1) {
        $db->rollBack();
        api_json(401, ['ok' => false, 'error' => 'signature_invalid']);
    }

    $mark = $db->prepare(
        'UPDATE api_challenges SET used_at = :used_at
         WHERE challenge_id = :id AND used_at IS NULL AND expires_at >= :now'
    );
    $mark->execute([':used_at' => time(), ':id' => $challengeId, ':now' => time()]);
    if ($mark->rowCount() !== 1) {
        $db->rollBack();
        api_json(401, ['ok' => false, 'error' => 'challenge_already_used']);
    }

    $token = api_random_token(32);
    $tokenHash = api_token_hash($token);
    $now = time();
    $tokenInsert = $db->prepare(
        'INSERT INTO api_tokens (token_hash, device_id, expires_at, revoked_at, created_at)
         VALUES (:token_hash, :device_id, :expires_at, NULL, :created_at)'
    );
    $tokenInsert->execute([
        ':token_hash' => $tokenHash,
        ':device_id' => $deviceId,
        ':expires_at' => $now + KP4000_TOKEN_TTL_SECONDS,
        ':created_at' => $now,
    ]);
    $db->commit();

    api_json(200, [
        'ok' => true,
        'access_token' => $token,
        'token_type' => 'Bearer',
        'expires_in' => KP4000_TOKEN_TTL_SECONDS,
    ]);
} catch (Throwable $e) {
    if (isset($db) && $db instanceof PDO && $db->inTransaction()) {
        $db->rollBack();
    }
    error_log('KP4000 verify endpoint failed: ' . $e->getMessage());
    api_json(500, ['ok' => false, 'error' => 'internal_error']);
}
