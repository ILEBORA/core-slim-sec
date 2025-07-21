<?php
use Dotenv\Dotenv;
$dotenv = Dotenv::createImmutable(__DIR__.'/../../../');
$dotenv->load();

define('CORE_SEC_PASSWORD', $_ENV['CORE_CLIENT_SECRET'] ?: 'mypassword');
$encrypted_code = file_get_contents(__DIR__ . '/core.bora');
$decrypted_code = openssl_decrypt($encrypted_code, 'AES-128-CTR', CORE_SEC_PASSWORD, 0, '1234567891011121');

if (!$decrypted_code) {
    die("Invalid credentials or corrupted core.sec.\n");
}
//Engage
eval($decrypted_code);