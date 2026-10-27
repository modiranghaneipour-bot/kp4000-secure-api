<?php
declare(strict_types=1);

require_once __DIR__ . '/common.php';

api_require_post();
$data = api_read_json();
$deviceId = api_string($data, 'device_id', 128);
$publicKeyPem = api_string($data, 'public_key', 8192);
$activationCode = api_string($data, 'activation_code', 32);

if (!preg_match('/^[A-Fa-f0-9]{32}$/', $activationCode)) {
    api_json(400, ['ok' => false, 'error' => 'invalid_activation_code']);
}
$publicKey = openssl_pkey_get_public($publicKeyPem);
if ($publicKey === false) {
    api_json(400, ['ok' => false, 'error' => 'invalid_public_key']);
}
$details = openssl_pkey_get_details($publicKey);
openssl_free_key($publicKey);
if (!is_array($details) || empty($details['key'])) {
    api_json(400, ['ok' => false, 'error' => 'invalid_public_key']);
}

$now = time();
$codeHash = hash('sha256', strtoupper($activationCode));

try {
    $db = api_db();
    $db->beginTransaction();

    $stmt = $db->prepare(
        'SELECT activation_code_hash, expires_at, used_at
         FROM device_activation_codes
         WHERE activation_code_hash = :hash
         LIMIT 1'
    );
    $stmt->execute([':hash' => $codeHash]);
    $code = $stmt->fetch();

    if (!$code || $code['used_at'] !== null ||
        ($code['expires_at'] !== null && (int)$code['expires_at'] < $now)) {
        $db->rollBack();
        api_json(401, ['ok' => false, 'error' => 'activation_code_invalid_or_expired']);
    }

    $existing = $db->prepare('SELECT device_id FROM devices WHERE device_id = :id LIMIT 1');
    $existing->execute([':id' => $deviceId]);
    if ($existing->fetch()) {
        $db->rollBack();
        api_json(409, ['ok' => false, 'error' => 'device_already_registered']);
    }

    $insertDevice = $db->prepare(
        "INSERT INTO devices (device_id, public_key, status, created_at, updated_at)
         VALUES (:id, :public_key, 'active', :created_at, :updated_at)"
    );
    $insertDevice->execute([
        ':id' => $deviceId,
        ':public_key' => $publicKeyPem,
        ':created_at' => $now,
        ':updated_at' => $now,
    ]);

    $consume = $db->prepare(
        'UPDATE device_activation_codes
         SET used_at = :now, bound_device_id = :device_id
         WHERE activation_code_hash = :hash AND used_at IS NULL
           AND (expires_at IS NULL OR expires_at >= :now_check)'
    );
    $consume->execute([
        ':now' => $now,
        ':device_id' => $deviceId,
        ':hash' => $codeHash,
        ':now_check' => $now,
    ]);
    if ($consume->rowCount() !== 1) {
        $db->rollBack();
        api_json(401, ['ok' => false, 'error' => 'activation_code_invalid_or_expired']);
    }

    $db->commit();
    api_json(201, ['ok' => true, 'device_id' => $deviceId, 'status' => 'active']);
} catch (Throwable $e) {
    if (isset($db) && $db instanceof PDO && $db->inTransaction()) {
        $db->rollBack();
    }
    error_log('KP4000 registration endpoint failed: ' . $e->getMessage());
    api_json(500, ['ok' => false, 'error' => 'internal_error']);
}
