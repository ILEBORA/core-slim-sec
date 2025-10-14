<?php
/**
 * ================================================================
 *  BoraSlim Secure Distribution
 *  Framework:  ilebora/core-slim-sec
 *  Version:    2.1.2
 *  Build ID:   34BCE5166E49
 *  Timestamp:  2025-10-14 09:01:46
 *  License:    Proprietary - Unauthorized modification or redistribution prohibited.
 *  Contact:
 *  support@boracore.co.ke
 *  ileboratech@gmail.com
 *  +254 113 703 323
 * 
 *  Notice:
 *  This file is part of the BoraSlim Framework.
 *  Unauthorized modification or redistribution is prohibited.
 * 
 *  © 2025 ILEBORA Technologies. All Rights Reserved.
 * ================================================================
 */
use Dotenv\Dotenv;

// 1️⃣ Resolve the client env folder
$basePath = realpath(__DIR__ . '/../../../../'); // App root (4 levels up from vendor)

// Allow client to define their env folder location
if (!defined('CORE_SECURE_APP_FOLDER')) {
    define('CORE_SECURE_APP_FOLDER', 'secure/core-landing');
}

// Resolve absolute env path
$envPath = realpath($basePath . '/' . CORE_SECURE_APP_FOLDER);

// 2️⃣ Load the app-specific .env
if ($envPath && file_exists($envPath . '/.env')) {
    $dotenv = Dotenv::createImmutable($envPath);
    $dotenv->safeLoad();
} else {
    error_log("⚠️ [CORE] No .env found in " . ($envPath ?: CORE_SECURE_APP_FOLDER));
}

// 3️⃣ Load the shared .system.env (if present)
$systemPaths = [
    $envPath . '/.system.env',          // inside same folder
    dirname($envPath) . '/.system.env', // or one folder up
];

foreach ($systemPaths as $systemFile) {
    if ($systemFile && file_exists($systemFile)) {
        $dotenvSys = Dotenv::createImmutable(dirname($systemFile), basename($systemFile));
        $dotenvSys->safeLoad();
        break;
    }
}

define('CORE_SEC_PASSWORD', $_ENV['CORE_CLIENT_SECRET'] ?? 'BoraSlim_Core_v1@Secure');
define('CORE_CLIENT_ID', $_ENV['CORE_CLIENT_ID'] ?? '');
define('CORE_CLIENT_IV', $_ENV['CORE_CLIENT_IV'] ?? '');
define('CORE_SERVER', 'https://boracore.co.ke');

// env var or fixed path outside vendor
$cacheDir = $_ENV['CORE_CACHE_PATH'] ?? __DIR__ . '/../../../.cache';
if (!is_dir($cacheDir)) {
    mkdir($cacheDir, 0777, true);
}

$cachePath   = $cacheDir . '/.core.cached.bora';
$hashPath    = $cachePath . '.hash';
$versionFile = $cacheDir . '/.core.version';
$defaultVersion = 'v1.0.0';

// --- Version setup ---
if (!file_exists($versionFile)) {
    file_put_contents($versionFile, $defaultVersion);
    $currentVersion = $defaultVersion;
} else {
    $currentVersion = trim(file_get_contents($versionFile));
}

// --- Handle missing core ---
if (!file_exists($cachePath)) {
    $currentVersion = ''; // force download
}

// --- Fetch remote version ---
if (isSameOrigin(CORE_SERVER)) {
    $remoteVersion = @file_get_contents('.core/.config/.version');
} else {
    $remoteVersion = @file_get_contents(CORE_SERVER . '/latest-version');
}

$remoteVersion  = extractVersion($remoteVersion);
$currentVersion = extractVersion($currentVersion);

// --- Auto update if needed ---
if ($remoteVersion && $currentVersion && version_compare($currentVersion, $remoteVersion, '<')) {
    error_log("New core version available. Downloading...\n");

    if (!isSameOrigin(CORE_SERVER)) {
        $response = @file_get_contents(
            CORE_SERVER . "/download?client_id=" . urlencode(CORE_CLIENT_ID)
        );
    } else {
        if (function_exists('handleCoreDownload')) {
            $response = handleCoreDownload(CORE_CLIENT_ID);
        } else {
            die("Local download handler not found.");
        }
    }

    if (!$response) {
        die("Failed to download new core.");
    }

    file_put_contents($cachePath, $response);
    file_put_contents($versionFile, $remoteVersion);
}

// --- 🔐 INTEGRITY VERIFICATION ---
if (!file_exists($cachePath)) {
    die("❌ Core file missing: $cachePath");
}

$encrypted = file_get_contents($cachePath);
$computedHash = hash('sha256', $encrypted);

if (file_exists($hashPath)) {
    $expectedHash = trim(file_get_contents($hashPath));
    if (!hash_equals($expectedHash, $computedHash)) {
        http_response_code(500);
        die("❌ Integrity check failed! Core file may be corrupted or tampered with.");
    }
} else {
    // Optional: look for embedded hash
    if (preg_match('/SHA256:\s*([a-f0-9]{64})/i', $encrypted, $match)) {
        $expectedHash = $match[1];
        if (!hash_equals($expectedHash, $computedHash)) {
            http_response_code(500);
            die("❌ Embedded signature mismatch. Aborting execution.");
        }
    } else {
        http_response_code(500);
        die("⚠️ No integrity signature found for core file.");
    }
}

// Validate
$clientIv = hex2bin(CORE_CLIENT_IV);
$clientSecret = CORE_SEC_PASSWORD;
if (strlen($clientSecret) < 32 || strlen($clientSecret) < 32) {
    throw new \RuntimeException("Invalid client secret or IV format.");
}

//decrypt
$decrypted = openssl_decrypt(
    $encrypted,
    'AES-256-CTR',
    $clientSecret,
    0,
    $clientIv
);

// --- Sanity checks ---
if (
    $decrypted === false ||
    !is_string($decrypted) ||
    strlen(trim($decrypted)) < 100 ||
    !preg_match('/namespace\s+[a-zA-Z0-9_\\\\]+;/', $decrypted)
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


