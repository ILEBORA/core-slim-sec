<?php

return [

    /* ==================================================
       vendor
    ================================================== */

    'jquery' => [
        'file'     => 'vendor/jquery.js',
        'type'     => 'library',
        'version'  => '3.7.1',
        'priority' => 1,
        // 'bypass'  => true,
        'preload'  => true,
        // 'global'    => "jQuery"
    ],

    'jquery_global' => [
        'file'     => 'vendor/jquery_global.js',
        'version'  => '1.0.0',
        'priority' => 2,
        // //'bypass'  => true,
        // 'preload'  => true,
    ],

    'select2' => [
        'file'     => 'vendor/select2.js',
        'version'  => '4.1.0',
        'priority' => 3,
        // 'global'   => 'select2',
        'bypass'  => true,
        'preload'  => false,
    ],

    'colorpicker' => [
        'file'     => 'vendor/colorpicker.js',
        'version'  => '1.0.0',
        'priority' => 4,
        'global'   => 'colorpicker',
        //'bypass'  => true,
        'preload'  => true,
    ],

    'draggable' => [
        'file'     => 'vendor/draggable.js',
        'version'  => '1.0.0',
        'priority' => 5,
        'global'   => 'draggable',
        //'bypass'  => true,
        'preload'  => true,
    ],

     'lib.cropper' => [
        'file'     => 'vendor/lib.cropper.js',
        'version'  => '1.0.0',
        'priority' => 5,
        'global'   => 'lib.cropper',
        //'bypass'  => true,
        'preload'  => true,
    ],

    'swiper' => [
        'file'     => 'vendor/swiper.js',
        'version'  => '1.0.0',
        'priority' => 4,
        'global'   => 'Swiper',
        //'bypass'  => true,
        'preload'  => true,
    ],

    /* ==================================================
       core engine
    ================================================== */

    'loader' => [
        'file'     => 'app/loader_old.js',
        'version'  => '1.0.0',
        'priority' => 10,
        'global'   => 'BORA',
        'preload'  => true,
    ],

    'runtime' => [
        'file'     => 'runtime_old.js',
        'version'  => '2.0.0',
        'priority' => 11,
        'global'   => 'runtime',
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
        'requires' => [],
        // 'preload'  => true,
    ],

    'ui.dom' => [
        'file'     => 'services/ui.dom.js',
        'type' => 'service', 
        'version'  => '1.0.0',
        'priority' => 27,
        'requires' => [],
        // 'preload'  => true,
    ],


    'router' => [
        'file'     => 'services/router.js',
        'type' => 'service', 
        'version'  => '1.0.0',
        'priority' => 28,
        'requires' => [ 'state'],
        // 'preload'  => true,
    ],

    'permissions' => [
        'file'     => 'services/permissions.js',
        'type' => 'service', 
        'version'  => '1.0.0',
        'priority' => 38,
        'requires' => [],
        // 'preload'  => true,
    ],

    'navigation' => [
        'file'     => 'services/navigation.js',
        'type' => 'service', 
        'version'  => '1.0.0',
        'priority' => 29,
        'requires' => [ 'router', 'state'],
        // 'preload'  => true,
    ],

    'breadcrumbs' => [
        'file'     => 'services/breadcrumbs.js',
        'type' => 'service', 
        'version'  => '1.0.0',
        'priority' => 30,
        // 'requires' => [ 'router', 'state'],
        // 'preload'  => true,
    ],

    'pipeline' => [
        'file'     => 'services/pipeline.js',
        'type' => 'service', 
        'version'  => '1.0.0',
        'priority' => 31,
        // 'requires' => [ 'router', 'state'],
        // 'preload'  => true,
    ],

    'uid' => [
        'file'     => 'services/uid.js',
        'type' => 'service', 
        'version'  => '1.0.0',
        'priority' => 32,
        // 'requires' => [ 'router', 'state'],
        // 'preload'  => true,
    ],

    /* ==================================================
       remaining services (lazy)
    ================================================== */

    'callbora' => ['file' => 'services/callbora.js', 'type' => 'service', 'version' => '2.0.0', 'priority' => 20, 'requires' => []],
    'hooks' => ['file' => 'services/hooks.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 21, 'requires' => []],
    'cache' => ['file' => 'services/cache.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 22, 'preload'=>false, 'requires' => []],
    'logger' => ['file' => 'services/logger.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 23, 'preload'=>true, 'requires' => []],
    'plugin' => ['file' => 'services/plugin.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 24, 'preload'=>true, 'requires' => []],
    'deprecations' => ['file' => 'services/deprecations.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 25, 'requires' => []],
    'meta' => ['file' => 'services/meta.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 27],
    'devtools' => ['file' => 'services/devtools.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 30, 'requires' => [ 'state']],
    'job.queue' => ['file' => 'services/job.queue.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 31, 'requires' => [ 'callbora']],
    'face' => ['file' => 'services/face.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 32, 'requires' => []],
    'menu' => ['file' => 'services/menu.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 33, 'requires' => []],
    'context' => ['file' => 'services/context.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 34, 'requires' => []],
    'resources' => ['file' => 'services/resources.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 35, 'requires' => []],
    
    'capability' => ['file' => 'services/capability.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 36, 'requires' => []],
    'ui.actions' => ['file' => 'services/ui.actions.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 37, 'requires' => []],
    'ui.stack' => ['file' => 'services/ui.stack.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 39, 'preload'=>true,'requires' => []],
    'forms' => ['file' => 'services/forms.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 28, 'preload'=>true,'requires' => []],
    
    'ui.dismissable' => ['file' => 'services/ui.dismissable.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 40,'preload'=>true, 'requires' => []],
    'ui.element.dismiss' => ['file' => 'services/ui.element.dismiss.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 41, 'requires' => []],
    'preferences' => ['file' => 'services/preferences.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 42, 'requires' => []],
    'sanity' => ['file' => 'services/sanity.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 43, 'requires' => []],
    'pagecache' => ['file' => 'services/page-cache.js', 'type' => 'service', 'version' => '1.0.0', 'priority' => 44, 'requires' => []],
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
        'requires' => ['jquery', ]
    ],
    'events' => [
        'file' => 'plugins/events.js',
        'type' => 'plugin',
        'version' => '1.0.0',
        'priority' => 40,
        'requires' => ['jquery', ]
    ],
    'popup.core' => ['file' => 'plugins/popup.core.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 41, 'requires' => ['jquery',  'events'],'preload'=>false],
    'navigation.plugin' => ['file' => 'plugins/navigation.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 42],
    'alerts' => ['file' => 'plugins/alerts.js', 'type' => 'plugin', 'version' => '2.0.0', 'preload'=>false, 'priority' => 45, 'requires' => []],
    'breadcrumbs.plugin' => ['file' => 'plugins/breadcrumbs.plugin.js', 'type' => 'plugin', 'version' => '2.0.0', 'priority' => 45, 'requires' => []],

    'devtools.plugin' => ['file' => 'plugins/devtools.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 50],
    'app.core' => ['file' => 'plugins/app.core.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 55, 'requires' => ['hooks', 'state', 'callbora']],
    'layouts' => ['file' => 'plugins/layouts.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 57,'preload'=>false],
    'face.guest' => ['file' => 'plugins/face.guest.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 57],
    'face.client' => ['file' => 'plugins/face.client.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 58],
    'face.admin' => ['file' => 'plugins/face.admin.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 59],
    'layout.sidebar' => ['file' => 'plugins/layout.sidebar.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 60,'preload'=>false],
    'navigation.binder' => ['file' => 'plugins/navigation.binder.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 61, 'requires' => [ 'store', 'layout.sidebar']],
    'overlay' => ['file' => 'plugins/overlay.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 61, 'preload' => true],
    'logout.ux' => ['file' => 'plugins/logout.ux.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 62, 'preload' => true],
    // 'content.manager' => ['file' => 'plugins/content.manager.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 63, 'requires' => [ 'store'], 'preload' => true],

    'popup' => ['file' => 'plugins/popup.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 64, 'requires' => [ 'popup.core'], 'preload'=>false],
    
    'ui.bindings' => ['file' => 'plugins/ui.bindings.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 65, 'preload'=>false, 'requires' => [ 'state.reactive']],
    'store' => ['file' => 'plugins/store.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 66, 'requires' => [],'preload'=>false],
    'state.reactive' => ['file' => 'plugins/state.reactive.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 67, 'requires' => []],
    'component.mounter' => ['file' => 'plugins/component-mounter.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 68, 'preload'=>false, 'requires' => []],
    'key.handlers' => ['file' => 'plugins/key.handlers.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 69, 'requires' => []],
    'ui.tabs' => ['file' => 'plugins/ui.tabs.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 70, 'preload' => true, 'requires' => []],
    'entity.lifecycle' => ['file' => 'plugins/entity.lifecycle.js', 'type' => 'plugin', 'version' => '1.0.0', 'priority' => 71,'preload'=>false, 'requires' => []],


    /* ==================================================
       app layer (lazy)
    ================================================== */

    'ilebora_or' => ['file' => 'app/ilebora_or.js', 'version' => '1.0.0', 'priority' => 70, 'preload' => true ],
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


