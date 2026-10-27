<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

function api_json(int $status, array $payload): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, max-age=0');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function api_require_post(): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        header('Allow: POST');
        api_json(405, ['ok' => false, 'error' => 'method_not_allowed']);
    }
}

function api_read_json(): array
{
    $length = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($length > KP4000_MAX_REQUEST_BYTES) {
        api_json(413, ['ok' => false, 'error' => 'request_too_large']);
    }
    $raw = file_get_contents('php://input');
    if ($raw === false || trim($raw) === '') {
        api_json(400, ['ok' => false, 'error' => 'empty_request']);
    }
    try {
        $data = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
    } catch (JsonException $e) {
        api_json(400, ['ok' => false, 'error' => 'invalid_json']);
    }
    if (!is_array($data)) {
        api_json(400, ['ok' => false, 'error' => 'json_object_required']);
    }
    return $data;
}

function api_string(array $data, string $key, int $maxLength = 4096): string
{
    $value = $data[$key] ?? null;
    if (!is_string($value) || $value === '' || strlen($value) > $maxLength) {
        api_json(400, ['ok' => false, 'error' => 'invalid_' . $key]);
    }
    return $value;
}

function api_db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    $path = kp4000_database_path();
    if (!is_file($path) || !is_readable($path)) {
        error_log('KP4000 database missing or unreadable: ' . $path);
        api_json(500, ['ok' => false, 'error' => 'database_unavailable']);
    }
    try {
        $pdo = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        $pdo->exec('PRAGMA foreign_keys = ON');
        $pdo->exec('PRAGMA busy_timeout = 5000');
    } catch (Throwable $e) {
        error_log('KP4000 database connection failed: ' . $e->getMessage());
        api_json(500, ['ok' => false, 'error' => 'database_unavailable']);
    }
    return $pdo;
}

function api_random_token(int $bytes = 32): string
{
    return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
}

function api_token_hash(string $token): string
{
    return hash('sha256', $token);
}
