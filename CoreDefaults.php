<?php
/**
 * ================================================================
 *  BoraSlim Secure Distribution
 *  Framework:  ilebora/core-slim-sec
 *  Version:    2.1.1
 *  Build ID:   9BFCA31C1A56
 *  Timestamp:  2025-10-05 09:32:48
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

// Only set timezone if not already defined
if (!ini_get('date.timezone')) {
    date_default_timezone_set("Africa/Nairobi");
}

// Default error handling
error_reporting(E_ALL);
ini_set('ignore_repeated_errors', TRUE);

// Default display_errors based on environment
if (php_sapi_name() !== 'cli' && ($_SERVER['REMOTE_ADDR'] ?? '') !== '::1') {
    ini_set('display_errors', false);
    // die('Admin2' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
}

// ini_set('log_errors', TRUE);
// ini_set('error_log', __DIR__ . '/../../.logs/errors.log'); // relative to vendor dir
// ini_set('log_errors_max_len', 1024);

$defaultLogPath = dirname(__DIR__, 3) . '/.logs/errors.log'; // resolves to project root

if (!file_exists(dirname($defaultLogPath))) {
    mkdir(dirname($defaultLogPath), 0777, true); // Create logs directory if not exists
}

ini_set('log_errors', true);

// Only set if not already overridden
if (!ini_get('error_log')) {
    ini_set('error_log', $defaultLogPath);
}

ini_set('log_errors_max_len', 1024);

// Define REQUEST_SCHEME only if not defined
if (!defined('REQUEST_SCHEME')) {
    if (
        (!empty($_SERVER['REQUEST_SCHEME']) && $_SERVER['REQUEST_SCHEME'] === "https") ||
        (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === "on") ||
        (!empty($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443)
    ) {
        define("REQUEST_SCHEME", "https");
    } else {
        define("REQUEST_SCHEME", "http");
    }
}

// Define BASE_DIR etc. only if not already defined
if (!defined("BASE_DIR")) {
    define("BASE_DIR", dirname(__DIR__, 3));
    if(isset($_SERVER['DOCUMENT_ROOT']) && !empty(isset($_SERVER['DOCUMENT_ROOT']))){
        $baseUrlRelative = !empty($_SERVER['DOCUMENT_ROOT']) ?  explode($_SERVER['DOCUMENT_ROOT'], str_replace(DIRECTORY_SEPARATOR, "/", BASE_DIR))[1] : '';
        define("BASE_URL_RELATIVE", $baseUrlRelative . '/');
    }else{
         define("BASE_URL_RELATIVE", '/'); 
    }
    $lnkfix = (BASE_URL_RELATIVE == "/") ? "/" : BASE_URL_RELATIVE;
    if(isset($_SERVER['HTTP_HOST'])){
        define("BASE_URL", REQUEST_SCHEME . '://' . $_SERVER['HTTP_HOST'] . $lnkfix);
    }else{
        define("BASE_URL", REQUEST_SCHEME . '://' . $lnkfix);
    }
    
    define("SITEROOT", str_replace("/", "", BASE_URL_RELATIVE));
    $_SESSION['BASE_DIR'] = BASE_URL;
}

// die(BASE_URL);
//TODO:: start session if user needs