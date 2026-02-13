<?php
/**
 * ================================================================
 *  BoraSlim Secure Distribution
 *  Framework:  ilebora/core-slim-sec
 *  Version:    2.1.10
 *  Build ID:   5023C25483F2
 *  Timestamp:  2026-02-13 13:25:06
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
define('CORE_SERVER', 'https://ilebora.co.ke');

// env var or fixed path outside vendor
$cacheDir = $_ENV['CORE_CACHE_PATH'] ?? __DIR__ . '/../../../.cache';
if (!is_dir($cacheDir)) {
    mkdir($cacheDir, 0777, true);
}

$cachePath   = $cacheDir . '/.core.cached.bora';
$hashPath    = $cachePath . '.hash';
$versionFile = $cacheDir . '/.core.version';
$defaultVersion = 'v1.0.0';

$jsCachePath = $cacheDir . '/.js-core.cached.bora';
$jsHashPath    = $cachePath . '.js-core.cached.bora.hash';

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
    file_put_contents($cachePath, '');
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
    error_log("New core version $remoteVersion available. Downloading...\n");

    if (!isSameOrigin(CORE_SERVER)) {
        $response = @file_get_contents(
            CORE_SERVER . "/download?client_id=" . urlencode(CORE_CLIENT_ID)
        );
    } else {
        if (function_exists('handleCoreDownload')) {
            $response = handleCoreDownload(CORE_CLIENT_ID);
        } else {
            error_log("❌ Local download handler not found.");
            die("Local download handler not found.");
        }
    }

    if (!$response) {
        error_log("❌ Failed to download new core.");
        die("Failed to download new core.");
    }

    file_put_contents($cachePath, $response);
    file_put_contents($versionFile, $remoteVersion);

    //create a hash
    $newHash = hash('sha256', $response);
    file_put_contents($hashPath, $newHash);

    // Dublicate for JS
    if (!isSameOrigin(CORE_SERVER)) {
        $response = @file_get_contents(
            CORE_SERVER . "/download-js?client_id=" . urlencode(CORE_CLIENT_ID)
        );
    } else {
        if (function_exists('handleCoreDownload')) {
            $response = handleCoreDownload(CORE_CLIENT_ID);
        } else {
            error_log("❌ Local download handler not found.");
            die("Local download handler not found.");
        }
    }

    if (!$response) {
        error_log("❌ Failed to download new core.");
        die("Failed to download new core.");
    }

    file_put_contents($jsCachePath, $response);
    // file_put_contents($versionFile, $remoteVersion);

    //create a hash
    $newHash = hash('sha256', $response);
    file_put_contents($jsHashPath, $newHash);

}

// --- 🔐 INTEGRITY VERIFICATION ---
if (!file_exists($cachePath)) {
    // var_dump(ini_get('error_log'));
    error_log("❌ Core file missing: $cachePath");
    die("❌ Core file missing: $cachePath");
}

$encrypted = file_get_contents($cachePath);
$computedHash = hash('sha256', $encrypted);

if (file_exists($hashPath)) {
    $expectedHash = trim(file_get_contents($hashPath));
    if (!hash_equals($expectedHash, $computedHash)) {
        //http_response_code(500);
        error_log("❌ Integrity check failed! Core file may be corrupted or tampered with.");
        die("❌ Integrity check failed! Core file may be corrupted or tampered with.");
    }
} else {
    // Optional: look for embedded hash
    if (preg_match('/SHA256:\s*([a-f0-9]{64})/i', $encrypted, $match)) {
        $expectedHash = $match[1];
        if (!hash_equals($expectedHash, $computedHash)) {
            //http_response_code(500);
            error_log("❌ Embedded signature mismatch. Aborting execution.");
            die("❌ Embedded signature mismatch. Aborting execution.");
        }
    } else {
        //http_response_code(500);
        error_log("⚠️ No integrity signature found for core file.");
        die("⚠️ No integrity signature found for core file.");
    }
}
function secureEval(string $code): void
{
    if (debugDetected()) {
        throw new \RuntimeException("Debug environment detected.");
    }

    eval($code);
}
function debugDetected(): bool
{
    return extension_loaded('xdebug')
        || ini_get('xdebug.mode')
        //|| ini_get('display_errors') === '1'
        ;
}
$signatureFile = __DIR__ . '/app.sig';
if (!file_exists($signatureFile)) {
    die("Missing loader signature.");
}
$signature = base64_decode(file_get_contents($signatureFile));
$data = file_get_contents(__FILE__);
$publicKey = base64_decode('LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdThqVE5ZZzF3RmsxeFdaYzdsa0UNCktUUTNDSlczb2JTYkcwcmdDUVlsZVRMNU1ZZEdpcEt3UVI3QWxrcWNNYTFxdVc4Z1VnVDFZcFhYNEE2Qkg3bk0NCk9obDJpaG5GRTVva05MZGxBbFJPdFI0ek56UFhnbEVtT3B3b0xWZ3NmajVWcnFsVnkxcGJ5UmFWS3pxT3VhRTQNCnZUa1RtajhUdVgrazN1U0tKNnFtWnVSRFlZV0h0eDlaazY2dVZlWnFzL1F4SU5qaHNjRzFPUlEzV00yaTFZNWsNCnBtQVJ6VUxqeW5hcVFLMmJ0UFhYQ1NDUmdKeTJ5RFBIR2RPMVFDRWM1d1pQeE1sMzlmTWMzOU5aQmlXeGVSNG4NCjBDVjlyME5IMFA5TDZwTDg4bVQ0RWl6c0NLVWxCL3ZFSkl6TjRKa3ZzWUFDczFEOXNnbU9YS1Jvbm9WbkRRM00NCnhRSURBUUFCDQotLS0tLUVORCBQVUJMSUMgS0VZLS0tLS0NCg==')
$ok = openssl_verify(
    $data,
    $signature,
    $publicKey,
    OPENSSL_ALGO_SHA256
);
if ($ok !== 1) {
    die("Loader integrity compromised.");
}
unset($signature, $data);

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
    //http_response_code(500);
    if (file_exists($errorFile)) {
        readfile($errorFile);
    } else {
        echo "Decryption failed and error page is missing.";
    }
    exit;
}

// ==============================
// 🔐 JS CORE LOADER (NO EXECUTION)
// ==============================

$jsCoreDecrypted = null;

if (file_exists($jsCachePath)) {

    $jsEncrypted = file_get_contents($jsCachePath);
    $jsComputedHash = hash('sha256', $jsEncrypted);

    if (file_exists($jsHashPath)) {
        $jsExpectedHash = trim(file_get_contents($jsHashPath));

        if (!hash_equals($jsExpectedHash, $jsComputedHash)) {
            //http_response_code(500);
            error_log("❌ JS Core integrity check failed.");
            // die("❌ JS Core integrity check failed.");
        }
    } else {
        //http_response_code(500);
        error_log("❌ JS Core hash missing.");
        die("❌ JS Core hash missing.");
    }

    // Decrypt JS core
    $jsCoreDecrypted = openssl_decrypt(
        $jsEncrypted,
        'AES-256-CTR',
        $clientSecret,
        0,
        $clientIv
    );

    // Sanity checks (VERY important)
    if (
        $jsCoreDecrypted === false ||
        !is_string($jsCoreDecrypted) ||
        strlen(trim($jsCoreDecrypted)) < 50 ||
        !str_contains($jsCoreDecrypted, '@bora:chunk start')
    ) {
        //http_response_code(500);
        error_log("❌ JS Core decryption sanity check failed.");
        die("❌ JS Core decryption sanity check failed.");
    }

} else {
    // JS core optional, but log loudly
    error_log("⚠️ JS Core not found. UI capabilities will be limited.");
}

try {
    secureEval($decrypted);
    $decrypted = str_repeat("\0", strlen($decrypted));
    unset($decrypted);

    $GLOBALS['__BORA_JS_CORE__'] = $jsCoreDecrypted;
    $jsCoreDecrypted = str_repeat("\0", strlen($jsCoreDecrypted));
    unset($jsCoreDecrypted);

    $manifest = require 'asset-manifest.php';
    if (($manifest['asset_api'] ?? 0) < \BoraSlim\Core\Assets\AssetContract::REQUIRED_ASSET_API) {
        throw new RuntimeException(
            sprintf(
                'Core asset repo outdated. Required asset API %d, found %d. Run composer update.',
                \BoraSlim\Core\Assets\AssetContract::REQUIRED_ASSET_API,
                $manifest['asset_api'] ?? 0
            )
        );
    }
} catch (Throwable $e) {
    die("Core execution error: " . $e->getMessage());
}


