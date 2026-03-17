<?php

return [

    /* ==================================================
       VENDOR (Load First – Pure Dependencies)
    ================================================== */

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


    /* ==================================================
       CORE ENGINE (Execution Container)
    ================================================== */

    'runtime' => [
        'file'     => 'runtime.js',
        'version'  => '2.0.0',
        'priority' => 10,
    ],


    /* ==================================================
       CORE SERVICES (Infrastructure Layer)
    ================================================== */

    'callbora' => [
        'file'     => 'services/callbora.js',
        'version'  => '2.0.0',
        'priority' => 20,
        'requires' => ['runtime']
    ],

    'hooks' => [
        'file'     => 'services/hooks.js',
        'version'  => '1.0.0',
        'priority' => 21,
        'requires' => ['runtime']
    ],

    'cache' => [
        'file'     => 'services/cache.js',
        'version'  => '1.0.0',
        'priority' => 22,
        'requires' => ['runtime']
    ],

    'logger' => [
        'file'     => 'services/logger.js',
        'version'  => '1.0.0',
        'priority' => 23,
        'requires' => ['runtime']
    ],

    'plugin' => [
        'file'     => 'services/plugin.js',
        'version'  => '1.0.0',
        'priority' => 24,
        'requires' => ['runtime']
    ],

    'deprecations' => [
        'file'     => 'services/deprecations.js',
        'version'  => '1.0.0',
        'priority' => 25,
        'requires' => ['runtime']
    ],

    'state' => [
        'file'     => 'services/state.js',
        'version'  => '1.0.0',
        'priority' => 26,
        'requires' => ['runtime']
    ],

    'meta' => [
        'file'     => 'services/meta.js',
        'version'  => '1.0.0',
        'priority' => 27,
    ],

    'router' => [
        'file'     => 'services/router.js',
        'version'  => '1.0.0',
        'priority' => 28,
        'requires' => ['runtime','state']
    ],

    'navigation' => [
        'file'     => 'services/navigation.js',
        'version'  => '1.0.0',
        'priority' => 29,
        'requires' => ['runtime','router','state']
    ],

    'devtools' => [
        'file'     => 'services/devtools.js',
        'version'  => '1.0.0',
        'priority' => 30,
        'requires' => ['runtime','state']
    ],

    'jobqueue' => [
        'file'     => 'services/job-queue.js',
        'version'  => '1.0.0',
        'priority' => 31,
        'requires' => ['runtime','callbora']
    ],

    'face' => [
        'file'     => 'services/face.js',
        'version'  => '1.0.0',
        'priority' => 32,
        'requires' => ['runtime']
    ],

    'menu' => [
        'file'     => 'services/menu.js',
        'version'  => '1.0.0',
        'priority' => 33,
        'requires' => ['runtime']
    ],

    'context' => [
        'file'     => 'services/context.js',
        'version'  => '1.0.0',
        'priority' => 34,
        'requires' => ['runtime']
    ],

    'popup.service' => [
        'file'     => 'services/popup.js',
        'version'  => '1.0.0',
        'priority' => 35,
        'requires' => ['runtime']
    ],

    'capability' => [
        'file'     => 'services/capability.js',
        'version'  => '1.0.0',
        'priority' => 36,
        'requires' => ['runtime']
    ],

    
    'ui.actions' => [
        'file'     => 'services/ui.actions.js',
        'version'  => '1.0.0',
        'priority' => 37,
        'requires' => ['runtime']
    ],

    'permissions' => [
        'file'     => 'services/permissions.js',
        'version'  => '1.0.0',
        'priority' => 38,
        'requires' => ['runtime']
    ],

    'ui.stack' => [
        'file'     => 'services/ui.stack.js',
        'version'  => '1.0.0',
        'priority' => 39,
        'requires' => ['runtime']
    ],

    'ui.dismissable' => [
        'file'     => 'services/ui.dismissable.js',
        'version'  => '1.0.0',
        'priority' => 40,
        'requires' => ['runtime']
    ],

    'ui.element.dismiss' => [
        'file'     => 'services/ui.element.dismiss.js',
        'version'  => '1.0.0',
        'priority' => 41,
        'requires' => ['runtime']
    ],

    'preferences' => [
        'file'     => 'services/preferences.js',
        'version'  => '1.0.0',
        'priority' => 42,
        'requires' => ['runtime']
    ],
    

    /* ==================================================
       CORE PLUGINS (UI Layer – Controlled)
    ================================================== */

    'events' => [
        'file'     => 'plugins/events.js',
        'version'  => '1.0.0',
        'priority' => 40,
        'requires' => ['jquery','runtime']
    ],

    'popup.plugin' => [
        'file'     => 'plugins/popup.js',
        'version'  => '1.0.0',
        'priority' => 41,
        'requires' => ['jquery','runtime','events']
    ],

    'navigation.plugin' => [
        'file'     => 'plugins/navigation.js',
        'version'  => '1.0.0',
        'priority' => 42,
        // 'requires' => ['jquery','runtime','events','navigation']
    ],

    'alerts' => [
        'file'     => 'plugins/alerts.js',
        'version'  => '2.0.0',
        'priority' => 45,
        'requires' => ['runtime']
    ],

    'devtools_plugin' => [
        'file'     => 'plugins/devtools.js',
        'version'  => '1.0.0',
        'priority' => 50,
        'requires' => ['devtools']
    ],

    'app_core' => [
        'file'     => 'plugins/app-core.js',
        'version'  => '1.0.0',
        'priority' => 55,
        'requires' => ['hooks','state','callbora']
    ],

    'layouts' => [
        'file'     => 'plugins/layouts.js',
        'version'  => '1.0.0',
        'priority' => 57,
    ],

    'face-guest' => [
        'file'     => 'plugins/face-guest.js',
        'version'  => '1.0.0',
        'priority' => 57,
    ],

    'face-client' => [
        'file'     => 'plugins/face-client.js',
        'version'  => '1.0.0',
        'priority' => 58,
    ],

    'face-admin' => [
        'file'     => 'app/face-admin.js',
        'version'  => '1.0.0',
        'priority' => 59,
    ],

    'layout.sidebar' => [
        'file'     => 'plugins/layout.sidebar.js',
        'version'  => '1.0.0',
        'priority' => 60,
    ],

    'navigation-binder' => [
        'file'     => 'plugins/navigation-binder.js',
        'version'  => '1.0.0',
        'priority' => 61,
    ],

    'overlay' => [
        'file'     => 'plugins/overlay.js',
        'version'  => '1.0.0',
        'priority' => 61,
    ],

    'logout.ux' => [
        'file'     => 'plugins/logout.ux.js',
        'version'  => '1.0.0',
        'priority' => 62,
    ],
    
    /* ==================================================
       APPLICATION LAYER (Project Specific)
    ================================================== */

    'ilebora_or' => [
        'file'     => 'app/ilebora_or.js',
        'version'  => '1.0.0',
        'priority' => 70,
    ],

    'mainjs' => [
        'file'     => 'app/mainjs.js',
        'version'  => '1.0.0',
        'priority' => 75,
    ],

    'config' => [
        'file' => '__inline__',
        'priority' => 76,
        'requires' => ['mainjs']
    ],

    'plugins' => [
        'file'     => 'app/plugins.js',
        'version'  => '1.0.0',
        'priority' => 80,
    ],

    


    /* ==================================================
       BOOTSTRAP (Always Last in Core)
    ================================================== */

    'bootstrap' => [
        'file'     => 'bootstrap.js',
        'version'  => '2.0.0',
        'priority' => 1000,
    ],


    /* ==================================================
       TENANT LAYER (Client Customization)
    ================================================== */

    'client' => [
        'file'     => 'tenant/client.js',
        'version'  => '1.0.0',
        'priority' => 1010,
    ],

];