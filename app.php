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

$defaultVersion = 'v1.0.0';

// Check if version file exists; if not create it
if (!file_exists($versionFile)) {
    file_put_contents($versionFile, $defaultVersion);
    $currentVersion = $defaultVersion;
} else {
    $currentVersion = trim(file_get_contents($versionFile));
}

// Check if core cache file exists; if not set currentVersion to empty to force download
if (!file_exists($cachePath)) {
    $currentVersion = ''; // force download since core file missing
}

// Get current and remote versions
// $remoteVersion = 'v1.0.2';// @file_get_contents(CORE_SERVER . '/latest-version');
if (isSameOrigin(CORE_SERVER)) {
    // die('here');
    $remoteVersion = @file_get_contents('.core/.config/.version');
} else {
    // die('there');
    $remoteVersion = @file_get_contents(CORE_SERVER . '/latest-version');
}

// die($remoteVersion);

$remoteVersion = extractVersion($remoteVersion);
$currentVersion = extractVersion($currentVersion);

if ($remoteVersion && $currentVersion) {
    if (version_compare($currentVersion, $remoteVersion, '<')) {
        error_log("New core version available. Downloading...\n");

        if (!isSameOrigin(CORE_SERVER)) {
            // Request the core encrypted for this client
            $response = @file_get_contents(
                CORE_SERVER . "/download?client_id=" . urlencode(CORE_CLIENT_ID)
            );
        }else{
            // Request the core encrypted for this client
            // die('here');
            if (class_exists('\App\Utils\Utils') && method_exists('\App\Utils\Utils', 'handleCoreDownload')) {
                $response = \App\Utils\Utils::handleCoreDownload(CORE_CLIENT_ID);
            } else {
                die("Local download handler not found.");
            }
        }

        if (!$response) {
            die("Failed to download new core.");
        }

        file_put_contents($cachePath, $response);
        file_put_contents($versionFile, $remoteVersion);
    }else{
        //echo you are up to date
    }
}else{
    //error parsing version
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