<?php
require  __DIR__ . '/../../../vendor/autoload.php';

// use BoraSlim\Core\Utils\EnvLoader;
EnvLoader::load(__DIR__ . '/../../../', 'wahenga');

$apiBase = rtrim(BASE_URL, '/') .'/api';
$apiVersion = 'v1';
?>

class BoraConfig {
    static API_BASE = "<?= $apiBase ?>";
    static API_VERSION = "<?= $apiVersion ?>";

    static get endpoint() {
        return `${this.API_BASE}/${this.API_VERSION}`;
    }
}