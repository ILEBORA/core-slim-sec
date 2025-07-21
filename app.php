<?php
use Dotenv\Dotenv;

$dotenv = Dotenv::createImmutable(__DIR__ . '/../../../');
$dotenv->load();

define('CORE_SEC_PASSWORD', $_ENV['CORE_CLIENT_SECRET'] ?? 'mypassword');
define('CORE_CLIENT_ID', $_ENV['CORE_CLIENT_ID'] ?? '');
define('CORE_CLIENT_IV', $_ENV['CORE_CLIENT_IV'] ?? '');

define('CORE_SERVER', 'https://boracore.co.ke');

// env var or fixed path outside vendor
$cacheDir = $_ENV['CORE_CACHE_PATH'] ?? __DIR__ . '/../../../.cache';
if (!is_dir($cacheDir)) {
    mkdir($cacheDir, 0777, true);
}

$cachePath = $cacheDir . '/.core.cached.bora';
$versionFile = $cacheDir . '/.core.version';

// Get current and remote versions
$currentVersion = file_exists($versionFile) ? trim(file_get_contents($versionFile)) : '';
$remoteVersion = @file_get_contents(CORE_SERVER . '/latest-version');

if ($remoteVersion && $currentVersion !== $remoteVersion) {
    echo "New core version available. Downloading...\n";

    // Request the core encrypted for this client
    $response = @file_get_contents(
        CORE_SERVER . "/download?client_id=" . urlencode(CORE_CLIENT_ID)
    );

    if (!$response) {
        die("Failed to download new core.");
    }

    file_put_contents($cachePath, $response);
    file_put_contents($versionFile, $remoteVersion);
}

$enc = file_get_contents($cachePath);

$decrypted = openssl_decrypt(
    $enc,
    'AES-128-CTR',
    CORE_SEC_PASSWORD,
    0,
    CORE_CLIENT_IV
);

// Validate content is not empty or corrupted
if (
    $decrypted === false ||
    !is_string($decrypted) ||
    strlen(trim($decrypted)) < 100 || // too short? suspicious
    !preg_match('/namespace\s+[a-zA-Z0-9_\\\\]+;/', $decrypted) // basic PHP structure
) {
    $errorFile = __DIR__ . '/resources/core-decryption-error.html';
    http_response_code(500);
    if (file_exists($errorFile)) {
        readfile($errorFile);
    } else {
        echo "Decryption failed and error page is missing.";
    }
    exit;
    
}

try {
    eval($decrypted);
} catch (Throwable $e) {
    die("Core execution error: " . $e->getMessage());
}