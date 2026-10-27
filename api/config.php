<?php
declare(strict_types=1);

/**
 * KP4000 Secure API configuration.
 * Prefer server environment variables. Never commit production secrets.
 */
const KP4000_CHALLENGE_TTL_SECONDS = 120;
const KP4000_TOKEN_TTL_SECONDS = 86400;
const KP4000_MAX_REQUEST_BYTES = 16384;

function kp4000_database_path(): string
{
    $path = getenv('KP4000_DB_PATH');
    if ($path !== false && $path !== '') {
        return $path;
    }
    return '/home/helpscho/mydatabase/myfile.sqlite';
}
