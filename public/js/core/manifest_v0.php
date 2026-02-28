<?php

return [

    /* ===============================
       VENDOR (Load First)
    =============================== */

    'jquery' => [
        'file'     => 'vendor/jquery.js',
        'version'  => '3.7.1',
        'priority' => 1,
    ],

    'jquery_global' => [
        'file'     => 'vendor/jquery_global.js',
        'version'  => '1.0.0',
        'priority' => 2,
    ],

    'select2' => [
        'file'     => 'vendor/select2.js',
        'version'  => '4.1.0',
        'priority' => 3,
    ],

    'colorpicker' => [
        'file'     => 'vendor/colorpicker.js',
        'version'  => '1.0.0',
        'priority' => 4,
    ],

    'draggable' => [
        'file'     => 'vendor/draggable.js',
        'version'  => '1.0.0',
        'priority' => 5,
    ],

    /* ===============================
       CORE ENGINE
    =============================== */

    'runtime' => [
        'file'     => 'runtime.js',
        'version'  => '1.0.0',
        'priority' => 10,
    ],

    'callbora' => [
        'file'     => 'services/callbora.js',
        'version'  => '1.0.0',
        'priority' => 20,
    ],

    'events' => [
        'file'     => 'services/events.js',
        'version'  => '1.0.0',
        'priority' => 21,
    ],

    'hooks' => [
        'file'     => 'services/hooks.js',
        'version'  => '1.0.0',
        'priority' => 22,
    ],

    'cache' => [
        'file'     => 'services/cache.js',
        'version'  => '1.0.0',
        'priority' => 23,
    ],

    'logger' => [
        'file'     => 'services/logger.js',
        'version'  => '1.0.0',
        'priority' => 24,
    ],

    'plugin' => [
        'file'     => 'services/plugin.js',
        'version'  => '1.0.0',
        'priority' => 25,
    ],

    'deprecations' => [
        'file'     => 'services/deprecations.js',
        'version'  => '1.0.0',
        'priority' => 26,
    ],

    /* ===============================
       CORE PLUGINS
    =============================== */

    'popup' => [
        'file'     => 'plugins/popup.js',
        'version'  => '1.0.0',
        'priority' => 40,
        'requires' => ['runtime']
    ],

    'alerts' => [
        'file'     => 'plugins/alerts.js',
        'version'  => '2.0.0',
        'priority' => 50,
        'requires' => ['runtime']
    ],

    /* ===============================
       APPLICATION LAYER
    =============================== */

    'ilebora_or' => [
        'file'     => 'app/ilebora_or.js',
        'version'  => '1.0.0',
        'priority' => 70,
    ],

    'mainjs' => [
        'file'     => 'app/mainjs.js',
        'version'  => '1.0.0',
        'priority' => 80,
    ],

    'plugins' => [
        'file'     => 'app/plugins.js',
        'version'  => '1.0.0',
        'priority' => 80,
    ],

    /* ===============================
       BOOTSTRAP (ALWAYS LAST IN Core)
    =============================== */

    'bootstrap' => [
        'file'     => 'bootstrap.js',
        'version'  => '1.0.0',
        'priority' => 1000,
    ],

    /* ===============================
       TENANT|CLIENT LAYER
    =============================== */

    'client' => [
        'file'     => 'tenant/client.js',
        'version'  => '1.0.0',
        'priority' => 1010,
    ],

];