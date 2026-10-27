<?php
declare(strict_types=1);

require_once __DIR__ . '/common.php';

api_require_post();
$data = api_read_json();
$deviceId = api_string($data, 'device_id', 128);

try {
    $db = api_db();
    // The device must already be registered and explicitly active.
    $stmt = $db->prepare(
        "SELECT device_id FROM devices WHERE device_id = :device_id AND status = 'active' LIMIT 1"
    );
    $stmt->execute([':device_id' => $deviceId]);
    if (!$stmt->fetch()) {
        api_json(401, ['ok' => false, 'error' => 'device_not_active']);
    }

    $challengeId = bin2hex(random_bytes(16));
    $challenge = api_random_token(32);
    $expiresAt = time() + KP4000_CHALLENGE_TTL_SECONDS;

    $insert = $db->prepare(
        'INSERT INTO api_challenges (challenge_id, device_id, challenge_value, challenge_hash, expires_at, used_at, created_at)
         VALUES (:id, :device_id, :challenge_value, :challenge_hash, :expires_at, NULL, :created_at)'
    );
    $insert->execute([
        ':id' => $challengeId,
        ':device_id' => $deviceId,
        ':challenge_value' => $challenge,
        ':challenge_hash' => hash('sha256', $challenge),
        ':expires_at' => $expiresAt,
        ':created_at' => time(),
    ]);

    api_json(200, [
        'ok' => true,
        'challenge_id' => $challengeId,
        'challenge' => $challenge,
        'expires_in' => KP4000_CHALLENGE_TTL_SECONDS,
    ]);
} catch (Throwable $e) {
    error_log('KP4000 start endpoint failed: ' . $e->getMessage());
    api_json(500, ['ok' => false, 'error' => 'internal_error']);
}
