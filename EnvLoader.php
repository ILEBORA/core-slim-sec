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
use Dotenv\Dotenv;

class EnvLoader
{
    /**
     * Load both system and app-specific env files.
     *
     * @param string $baseDir   Reference directory (e.g., __DIR__)
     * @param string|null $appName Name of the app (e.g., 'core-landing', 'boraslim')
     * @param bool $required    Whether to throw errors if files are missing
     */
    public static function load(string $baseDir, ?string $appName = null, bool $required = true): void
    {
        // Normalize base dir and derive secure path
        $secureDir = realpath($baseDir . '/../secure');
        // die($secureDir);
        if (!$secureDir || !is_dir($secureDir)) {
            if ($required) {
                throw new RuntimeException("Secure folder not found at: " . $baseDir . '/../secure');
            }
            return;
        }

        // 1️⃣ Load system-wide .system.env (if exists)
        $systemEnv = $secureDir . '/.system.env';
        if (file_exists($systemEnv)) {
            $dotenv = Dotenv::createImmutable($secureDir, '.system.env');
            $dotenv->safeLoad(); // doesn’t throw if missing keys
        } elseif ($required) {
            throw new RuntimeException("System env missing: $systemEnv");
        }

        // 2️⃣ Load app-specific env (if provided)
        if ($appName) {
            $appPath = $secureDir . '/' . $appName;
            $appEnv = $appPath . '/.env';

            if (file_exists($appEnv)) {
                $dotenvApp = Dotenv::createImmutable($appPath);
                $dotenvApp->safeLoad();
            } elseif ($required) {
                throw new \RuntimeException("App env missing: $appEnv");
            }
        }
    }
}