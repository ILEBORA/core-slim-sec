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
        'version'  => '2.0.0',
        'priority' => 10,
    ],

    /* ===============================
       CORE SERVICES
    =============================== */

    'plugin' => [
        'file'     => 'services/plugin.js',
        'version'  => '1.0.0',
        'priority' => 20,
    ],

    'logger' => [
        'file'     => 'services/logger.js',
        'version'  => '1.0.0',
        'priority' => 21,
    ],

    'hooks' => [
        'file'     => 'services/hooks.js',
        'version'  => '1.0.0',
        'priority' => 22,
    ],

    'state' => [
        'file'     => 'services/state.js',
        'version'  => '1.0.0',
        'priority' => 23,
    ],

    'navigation' => [
        'file'     => 'services/navigation.js',
        'version'  => '1.0.0',
        'priority' => 24,
    ],

    'meta' => [
        'file'     => 'services/meta.js',
        'version'  => '1.0.0',
        'priority' => 25,
    ],

    'page_cache' => [
        'file'     => 'services/page-cache.js',
        'version'  => '1.0.0',
        'priority' => 26,
    ],

    'cache' => [
        'file'     => 'services/cache.js',
        'version'  => '1.0.0',
        'priority' => 27,
    ],

    'callbora' => [
        'file'     => 'services/callbora.js',
        'version'  => '1.0.0',
        'priority' => 28,
    ],

    'preferences' => [
        'file'     => 'services/preferences.js',
        'version'  => '1.0.0',
        'priority' => 29,
    ],

    'deprecations' => [
        'file'     => 'services/deprecations.js',
        'version'  => '1.0.0',
        'priority' => 30,
    ],

    'events' => [
        'file'     => 'services/events.js',
        'version'  => '1.0.0',
        'priority' => 31,
    ],

    'overlay_service' => [
        'file'     => 'services/overlay.js',
        'version'  => '1.0.0',
        'priority' => 32,
    ],

    'router' => [
        'file'     => 'services/router.js',
        'version'  => '1.0.0',
        'priority' => 33,
    ],


    'devtools' => [
        'file'     => 'services/devtools.js',
        'version'  => '1.0.0',
        'priority' => 34,
    ],

    'jobqueue' => [
        'file'     => 'services/jobQueue.js',
        'version'  => '1.0.0',
        'priority' => 31,
    ],

    /* ===============================
       CORE PLUGINS
    =============================== */

    'alerts' => [
        'file'     => 'plugins/alerts.js',
        'version'  => '2.0.0',
        'priority' => 40,
    ],

    'popup' => [
        'file'     => 'plugins/popup.js',
        'version'  => '1.0.0',
        'priority' => 41,
    ],

    'runtime_ux' => [
        'file'     => 'plugins/runtime-ux.js',
        'version'  => '1.0.0',
        'priority' => 42,
    ],

    'navigation_binder' => [
        'file'     => 'plugins/navigation-binder.js',
        'version'  => '1.0.0',
        'priority' => 43,
    ],

    'content_manager' => [
        'file'     => 'plugins/content-manager.js',
        'version'  => '1.0.0',
        'priority' => 44,
    ],

    'key_handlers' => [
        'file'     => 'plugins/key-handlers.js',
        'version'  => '1.0.0',
        'priority' => 45,
    ],

    'dom_reactivity' => [
        'file'     => 'plugins/dom-reactivity.js',
        'version'  => '1.0.0',
        'priority' => 46,
    ],

    'component_hunter' => [
        'file'     => 'plugins/component-hunter.js',
        'version'  => '1.0.0',
        'priority' => 47,
    ],

    'live_search' => [
        'file'     => 'plugins/live-search.js',
        'version'  => '1.0.0',
        'priority' => 48,
    ],

    'devtools_plugin' => [
        'file'     => 'plugins/devtools.js',
        'version'  => '1.0.0',
        'priority' => 55,
    ],

    'app_core' => [
        'file'     => 'plugins/app-core.js',
        'version'  => '1.0.0',
        'priority' => 60,
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

    'plugins_app' => [
        'file'     => 'app/plugins.js',
        'version'  => '1.0.0',
        'priority' => 85,
    ],

    /* ===============================
       BOOTSTRAP (ALWAYS LAST IN CORE)
    =============================== */

    'bootstrap' => [
        'file'     => 'bootstrap.js',
        'version'  => '2.0.0',
        'priority' => 1000,
    ],

    /* ===============================
       TENANT LAYER
    =============================== */

    'client' => [
        'file'     => 'tenant/client.js',
        'version'  => '2.0.0',
        'priority' => 1010,
    ],

];