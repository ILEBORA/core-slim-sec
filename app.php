<?php
/**
 * ================================================================
 *  BoraSlim Secure Distribution
 *  Framework:  ilebora/core-slim-sec
 *  Version:    2.1.17
 *  Build ID:   83A841027942
 *  Timestamp:  2026-06-14 15:50:36
 *  License:    Proprietary - Unauthorized modification prohibited.
 *  © 2025 ILEBORA Technologies. All Rights Reserved.
 * ================================================================
 */

declare(strict_types=1);

use Dotenv\Dotenv;

/* ================================================================
 | 1. ENVIRONMENT RESOLUTION
 * ================================================================ */

$basePath = realpath(__DIR__ . '/../../../../');

if (!defined('CORE_SECURE_APP_FOLDER')) {

    // Resolve project value from all possible sources
    $project =
        boraIdentity('project')
        ?? $_SERVER['PRJCT_MUST_BE_SET']
        ?? getenv('PRJCT_MUST_BE_SET')
        ?? null;

    // Resolve environment
    $environment =
        boraIdentity('environment')
        ?: ($_SERVER['APP_ENV']
        ?? getenv('APP_ENV')
        ?? 'development');
        
    define(
        'APP_ENV',
        strtolower((string)$environment)
    );

    define(
        'APP_BRANCH',
        boraIdentity('branch', 'unknown')
    );

    define(
        'APP_COMMIT',
        boraIdentity('commit', '')
    );

    define(
        'APP_DEPLOYED_AT',
        boraIdentity('deployed_at', '')
    );

    if ($project !== null) {

        define(
            'PRJCT_MUST_BE_SET',
            $project
        );

        define(
            'CORE_SECURE_APP_FOLDER',
            'secure/' . $project
        );

    } else {

        define(
            'CORE_SECURE_APP_FOLDER',
            'secure/core-landing'
        );
    }

    define(
        'CORE_RUNTIME_FOLDER',
        CORE_SECURE_APP_FOLDER .
        '/runtime/' .
        APP_ENV
    );
}

$envPath = realpath($basePath . '/' . CORE_SECURE_APP_FOLDER);

if ($envPath && file_exists($envPath . '/.env')) {
    Dotenv::createImmutable($envPath)->safeLoad();
}

/* ================================================================
 | 2. CORE CONFIG
 * ================================================================ */

define('CORE_SERVER', 'https://ilebora.co.ke');
define('CORE_SEC_PASSWORD', $_ENV['CORE_CLIENT_SECRET'] ?? '');
define('CORE_CLIENT_ID', $_ENV['CORE_CLIENT_ID'] ?? '');
define('CORE_CLIENT_IV', $_ENV['CORE_CLIENT_IV'] ?? '');

$cacheDir = $_ENV['CORE_CACHE_PATH'] ?? __DIR__ . '/../../../.cache';

if (!is_dir($cacheDir)) {
    mkdir($cacheDir, 0755, true);
}

$paths = [
    'core'        => $cacheDir . '/.core.cached.bora',
    'core_hash'   => $cacheDir . '/.core.cached.bora.hash',
    'js'          => $cacheDir . '/.js-core.cached.bora',
    'js_hash'     => $cacheDir . '/.js-core.cached.bora.hash',
    'version'     => $cacheDir . '/.core.version',
    'lastcheck'   => $cacheDir . '/.last_update_check',
    'fails'       => $cacheDir . '/.update_fail_count',
    'tamper_ping' => $cacheDir . '/.last_loader_tamper_ping',
];

/* ================================================================
 | 3. UTILITIES
 * ================================================================ */

function httpGet(string $url, int $timeout = 2): ?string
{
    $ctx = stream_context_create([
        'http' => [
            'timeout' => $timeout,
            'ignore_errors' => true
        ]
    ]);

    $res = @file_get_contents($url, false, $ctx);
    return $res !== false ? $res : null;
}

function debugDetected(): bool
{
    return extension_loaded('xdebug') || ini_get('xdebug.mode');
}

function secureEval(string $code): void
{
    if (debugDetected()) {
        throw new RuntimeException("Debug environment detected.");
    }
    eval($code);
}

function verifyHash(string $file, string $hashFile): bool
{
    if (!file_exists($file) || !file_exists($hashFile)) {
        return false;
    }

    return hash_equals(
        trim(file_get_contents($hashFile)),
        hash('sha256', file_get_contents($file))
    );
}

function tamperPing(array $paths): void
{
    if (!CORE_CLIENT_ID) return;

    $interval = 600; // 10 min throttle

    $last = file_exists($paths['tamper_ping'])
        ? (int) file_get_contents($paths['tamper_ping'])
        : 0;

    if (time() - $last < $interval) return;

    file_put_contents($paths['tamper_ping'], time());

    httpGet(
        CORE_SERVER . "/tamper?client=" . urlencode(CORE_CLIENT_ID),
        1
    );
}

/* ================================================================
 | 4. LOADER SIGNATURE VERIFICATION (ROOT TRUST)
 * ================================================================ */

$signatureFile = __DIR__ . '/app.sig';

if (!file_exists($signatureFile)) {
    http_response_code(500);
    exit("Missing loader signature.");
}

$signature = base64_decode(file_get_contents($signatureFile));
$data      = file_get_contents(__FILE__);
$publicKey = base64_decode('LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0NCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdThqVE5ZZzF3RmsxeFdaYzdsa0UNCktUUTNDSlczb2JTYkcwcmdDUVlsZVRMNU1ZZEdpcEt3UVI3QWxrcWNNYTFxdVc4Z1VnVDFZcFhYNEE2Qkg3bk0NCk9obDJpaG5GRTVva05MZGxBbFJPdFI0ek56UFhnbEVtT3B3b0xWZ3NmajVWcnFsVnkxcGJ5UmFWS3pxT3VhRTQNCnZUa1RtajhUdVgrazN1U0tKNnFtWnVSRFlZV0h0eDlaazY2dVZlWnFzL1F4SU5qaHNjRzFPUlEzV00yaTFZNWsNCnBtQVJ6VUxqeW5hcVFLMmJ0UFhYQ1NDUmdKeTJ5RFBIR2RPMVFDRWM1d1pQeE1sMzlmTWMzOU5aQmlXeGVSNG4NCjBDVjlyME5IMFA5TDZwTDg4bVQ0RWl6c0NLVWxCL3ZFSkl6TjRKa3ZzWUFDczFEOXNnbU9YS1Jvbm9WbkRRM00NCnhRSURBUUFCDQotLS0tLUVORCBQVUJMSUMgS0VZLS0tLS0NCg==');

$verified = openssl_verify(
    $data,
    $signature,
    $publicKey,
    OPENSSL_ALGO_SHA256
);

if ($verified !== 1) {
    error_log("🚨 Loader integrity compromised.");
    tamperPing($paths);
    // http_response_code(500);
    // exit("Loader integrity compromised.");
}

unset($signature, $data);

/* ================================================================
 | 5. LOCAL CORE BOOTSTRAP (MANDATORY)
 * ================================================================ */

if (!file_exists($paths['core'])) {
    exit("Core not installed.");
}

if (!verifyHash($paths['core'], $paths['core_hash'])) {
    error_log("🚨 Core integrity failure.");
    http_response_code(500);
    exit("Core integrity failure.");
}

$encrypted = file_get_contents($paths['core']);

$clientSecret = CORE_SEC_PASSWORD;
$clientIv     = hex2bin(CORE_CLIENT_IV);

if (strlen($clientSecret) < 32 || !$clientIv) {
    throw new RuntimeException("Invalid client secret or IV.");
}

$decrypted = openssl_decrypt(
    $encrypted,
    'AES-256-CTR',
    $clientSecret,
    0,
    $clientIv
);

if (
    $decrypted === false ||
    strlen(trim($decrypted)) < 100 ||
    !preg_match('/namespace\s+[a-zA-Z0-9_\\\\]+;/', $decrypted)
) {
    http_response_code(500);
    exit("Core decryption failed.");
}

/* ================================================================
 | 6. EXECUTE CORE FIRST
 * ================================================================ */

secureEval($decrypted);
unset($decrypted);

/* ================================================================
 | 7. OPTIONAL JS CORE
 * ================================================================ */

if (file_exists($paths['js']) && verifyHash($paths['js'], $paths['js_hash'])) {

    $jsEncrypted = file_get_contents($paths['js']);

    $jsDecrypted = openssl_decrypt(
        $jsEncrypted,
        'AES-256-CTR',
        $clientSecret,
        0,
        $clientIv
    );

    if ($jsDecrypted && strlen(trim($jsDecrypted)) > 50) {
        $GLOBALS['__BORA_JS_CORE__'] = $jsDecrypted;
    }
}

/* ================================================================
 | 8. BACKGROUND SAFE UPDATE (THROTTLED)
 * ================================================================ */

$autoUpdate = ($_ENV['CORE_AUTO_UPDATE'] ?? 'true') === 'true';

if ($autoUpdate) {

    $interval = 3600;
    $maxFails = 5;

    $lastCheck = file_exists($paths['lastcheck'])
        ? (int) file_get_contents($paths['lastcheck'])
        : 0;

    $failCount = file_exists($paths['fails'])
        ? (int) file_get_contents($paths['fails'])
        : 0;

    if (time() - $lastCheck > $interval && $failCount < $maxFails) {

        file_put_contents($paths['lastcheck'], time());

        $remoteVersion = httpGet(CORE_SERVER . '/latest-version');

        if ($remoteVersion) {

            $localVersion = file_exists($paths['version'])
                ? trim(file_get_contents($paths['version']))
                : '0.0.0';

            if (version_compare($localVersion, trim($remoteVersion), '<')) {

                $download = httpGet(
                    CORE_SERVER . "/download?client_id=" . urlencode(CORE_CLIENT_ID)
                );

                if ($download) {
                    file_put_contents($paths['core'], $download);
                    file_put_contents($paths['core_hash'], hash('sha256', $download));
                    file_put_contents($paths['version'], trim($remoteVersion));
                    file_put_contents($paths['fails'], 0);
                } else {
                    file_put_contents($paths['fails'], $failCount + 1);
                }
            }
        }
    }
}
