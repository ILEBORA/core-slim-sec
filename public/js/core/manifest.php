<?php

return [

    /* ==================================================
       vendor
    ================================================== */

    'jquery' => [
        'file'     => 'vendor/jquery.js',
        'version'  => '3.7.1',
        'priority' => 1,
        // 'bypass'  => true,
        // 'preload'  => true,
    ],

    'jquery_global' => [
        'file'     => 'vendor/jquery_global.js',
        'version'  => '1.0.0',
        'priority' => 2,
        // 'bypass'  => true,
        // 'preload'  => true,
    ],

    'select2' => [
        'file'     => 'vendor/select2.js',
        'version'  => '4.1.0',
        'priority' => 3,
        'bypass'  => true,
        'preload'  => true,
    ],

    'colorpicker' => [
        'file'     => 'vendor/colorpicker.js',
        'version'  => '1.0.0',
        'priority' => 4,
        'bypass'  => true,
        'preload'  => true,
    ],

    'draggable' => [
        'file'     => 'vendor/draggable.js',
        'version'  => '1.0.0',
        'priority' => 5,
        'bypass'  => true,
        'preload'  => true,
    ],

     'lib.cropper' => [
        'file'     => 'vendor/lib.cropper.js',
        'version'  => '1.0.0',
        'priority' => 5,
        'bypass'  => true,
        'preload'  => true,
    ],

    /* ==================================================
       core engine
    ================================================== */

    'loader' => [
        'file'     => 'app/loader.js',
        'version'  => '1.0.0',
        'priority' => 10,
        'preload'  => true,
    ],

    'runtime' => [
        'file'     => 'runtime.js',
        'version'  => '2.0.0',
        'priority' => 11,
        'preload'  => true,
    ],

    /* ==================================================
       core services
    ================================================== */

    'state' => [
        'file'     => 'services/state.js',
        'type' => 'service', 
        'version'  => '1.0.0',
        'priority' => 26,
        'requires' => ['runtime'],
        'preload'  => true,
    ],

    'router' => [
        'file'     => 'services/router.js',
        'type' => 'service', 
        'version'  => '1.0.0',
        'priority' => 28,
        'requires' => ['runtime', 'state'],
        'preload'  => true,
    ],

    'permissions' => [
        'file'     => 'services/permissions.js',
        'type' => 'service', 
        'version'  => '1.0.0',
        'priority' => 38,
        'requires' => ['runtime'],
        'preload'  => true,
    ],

    'navigation' => [
        'file'     => 'services/navigation.js',
        'type' => 'service', 
        'version'  => '1.0.0',
        'priority' => 29,
        'requires' => ['runtime', 'router', 'state'],
        'preload'  => true,
    ],

    'breadcrumbs' => [
        'file'     => 'services/breadcrumbs.js',
        'type' => 'service', 
        'version'  => '1.0.0',
        'priority' => 30,
        // 'requires' => ['runtime', 'router', 'state'],
        // 'preload'  => true,
    ],

    'pipeline' => [
        'file'     => 'services/pipeline.js',
        'type' => 'service', 
        'version'  => '1.0.0',
        'priority' => 31,
        // 'requires' => ['runtime', 'router', 'state'],
        // 'preload'  => true,
    ],

    'uid' => [
        'file'     => 'services/uid.js',
        'type' => 'service', 
        'version'  => '1.0.0',
        'priority' => 32,
        // 'requires' => ['runtime', 'router', 'state'],
        // 'preload'  => true,
    ],

    /* ==================================================
       remaining services (lazy)
    ================================================== */

    'callbora' => ['file' => 'services/callbora.js', 'type' => 'service', 'version' => '2.0.0', 'priority' => 20, 'requires' => ['runtime']],
    'hooks' => ['file' => 'services/hooks.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 21, 'requires' => ['runtime']],
    'cache' => ['file' => 'services/cache.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 22, 'preload'=>true, 'requires' => ['runtime']],
    'logger' => ['file' => 'services/logger.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 23, 'preload'=>true, 'requires' => ['runtime']],
    'plugin' => ['file' => 'services/plugin.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 24, 'preload'=>true, 'requires' => ['runtime']],
    'deprecations' => ['file' => 'services/deprecations.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 25, 'requires' => ['runtime']],
    'meta' => ['file' => 'services/meta.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 27],
    'devtools' => ['file' => 'services/devtools.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 30, 'requires' => ['runtime', 'state']],
    'job.queue' => ['file' => 'services/job.queue.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 31, 'requires' => ['runtime', 'callbora']],
    'face' => ['file' => 'services/face.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 32, 'requires' => ['runtime']],
    'menu' => ['file' => 'services/menu.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 33, 'requires' => ['runtime']],
    'context' => ['file' => 'services/context.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 34, 'requires' => ['runtime']],
    
    'capability' => ['file' => 'services/capability.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 36, 'requires' => ['runtime']],
    'ui.actions' => ['file' => 'services/ui.actions.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 37, 'requires' => ['runtime']],
    'uistack' => ['file' => 'services/ui.stack.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 39, 'requires' => ['runtime']],
    'ui.dismissable' => ['file' => 'services/ui.dismissable.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 40, 'requires' => ['runtime']],
    'ui.element.dismiss' => ['file' => 'services/ui.element.dismiss.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 41, 'requires' => ['runtime']],
    'preferences' => ['file' => 'services/preferences.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 42, 'requires' => ['runtime']],
    'sanity' => ['file' => 'services/sanity.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 43, 'requires' => ['runtime']],
    'pagecache' => ['file' => 'services/page-cache.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 44, 'requires' => ['runtime']],
    'sound' => ['file' => 'services/sound.service.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 45, 'requires' => []],
    'navigator' => ['file' => 'services/navigator.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 46, 'requires' => []],
    'route.registry' => ['file' => 'services/route.registry.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 47, 'requires' => []],

    'pipeline.image.validate' => ['file' => 'services/pipeline.image.validate.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 47, 'requires' => []],
    'pipeline.image.crop' => ['file' => 'services/pipeline.image.crop.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 47, 'requires' => []],
    'pipeline.image.compress' => ['file' => 'services/pipeline.image.compress.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 47, 'requires' => []],

    

    /* ==================================================
       core plugins (lazy)
    ================================================== */
    'agent.ui' => [
        'file' => 'plugins/agent.ui.js',
        'type' => 'plugin',
        'version' => '1.0.0',
        'priority' => 39,
        'requires' => ['jquery', 'runtime']
    ],
    'events' => [
        'file' => 'plugins/events.js',
        'type' => 'plugin',
        'version' => '1.0.0',
        'priority' => 40,
        'requires' => ['jquery', 'runtime']
    ],
    'popup.core' => ['file' => 'plugins/popup.core.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 41, 'requires' => ['jquery', 'runtime', 'events'],'preload'=>true],
    'navigation.plugin' => ['file' => 'plugins/navigation.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 42],
    'alerts' => ['file' => 'plugins/alerts.js', 'type' => 'plugin', 'version' => '2.0.0', 'priority' => 45, 'requires' => ['runtime']],
    'breadcrumbs.plugin' => ['file' => 'plugins/breadcrumbs.js', 'type' => 'plugin', 'version' => '2.0.0', 'priority' => 45, 'requires' => ['runtime']],

    'devtools.plugin' => ['file' => 'plugins/devtools.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 50],
    'app.core' => ['file' => 'plugins/app.core.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 55, 'requires' => ['hooks', 'state', 'callbora']],
    'layouts' => ['file' => 'plugins/layouts.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 57,'preload'=>true],
    'face.guest' => ['file' => 'plugins/face.guest.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 57],
    'face.client' => ['file' => 'plugins/face.client.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 58],
    'face.admin' => ['file' => 'plugins/face.admin.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 59],
    'layout.sidebar' => ['file' => 'plugins/layout.sidebar.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 60,'preload'=>true],
    'navigation.binder' => ['file' => 'plugins/navigation.binder.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 61, 'requires' => ['runtime', 'store', 'layout.sidebar']],
    'overlay' => ['file' => 'plugins/overlay.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 61, 'preload' => true],
    'logout.ux' => ['file' => 'plugins/logout.ux.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 62, 'preload' => true],
    'content.manager' => ['file' => 'plugins/content.manager.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 63, 'requires' => ['runtime', 'store'], 'preload' => true],

    'popup' => ['file' => 'plugins/popup.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 64, 'requires' => ['runtime', 'popup.core'], 'preload'=>true],
    
    'dom.reactivity' => ['file' => 'plugins/dom.reactivity.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 65, 'requires' => ['runtime', 'state.reactive']],
    'store' => ['file' => 'plugins/store.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 66, 'requires' => ['runtime'],'preload'=>true],
    'state.reactive' => ['file' => 'plugins/state.reactive.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 67, 'requires' => ['runtime']],
    'component.mounter' => ['file' => 'plugins/component-mounter.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 68, 'requires' => ['runtime']],
    'key.handlers' => ['file' => 'plugins/key.handlers.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 69, 'requires' => ['runtime']],
    'ui.tabs' => ['file' => 'plugins/ui.tabs.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 70, 'requires' => ['runtime']],
    


    /* ==================================================
       app layer (lazy)
    ================================================== */

    'ilebora_or' => ['file' => 'app/ilebora_or.js', 'version' => '1.0.0', 'priority' => 70, 'preload' => true, 'bypass' => true],
    'mainjs' => ['file' => 'app/mainjs.js', 'version' => '1.0.0', 'priority' => 75, 'preload' => true],    

    'config' => [
        'file' => '__inline__',
        'priority' => 76,
        'requires' => ['mainjs'],
        'preload' => true,
    ],

    'plugins' => ['file' => 'app/plugins.js', 'version' => '1.0.0', 'priority' => 80],

    /* ==================================================
       bootstrap
    ================================================== */

    'bootstrap' => [
        'file'     => 'bootstrap.js',
        'version'  => '2.0.0',
        'priority' => 1000,
        'preload'  => true,
    ],

    /* ==================================================
       tenant
    ================================================== */

    'client' => [
        'file'     => 'tenant/client.js',
        'version'  => '1.0.0',
        'priority' => 1010,
    ],

];


