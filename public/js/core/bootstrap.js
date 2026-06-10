/**
 * BoraCore Bootstrap
 * ----------------------------------------
 * Responsibilities:
 * - Initialize runtime
 * - Attach to global
 * - Preload minimal core (optional)
 * - Trigger first activation cycle
 * - Provide predictable startup lifecycle
 */

(function(global){

    'use strict';

    /* ==================================================
       CONFIG
    ================================================== */

    const CONFIG = global.__BORA_CONFIG__ || {
        dev: true, //rd('devMode', false), //false,
        // securityMode: 'strict'
    };

    // Minimal preload set (can be tuned per app)
    const CORE_PRELOAD = [
        'state',
        'router',
        'permissions',
        'alerts'
    ];

    /* ==================================================
       BOOT SEQUENCE
    ================================================== */

    async function boot(){

        if(global.__BORA_APP__){
            console.warn('[Bootstrap] App already initialized');
            return;
        }

        const startTime = performance.now();

        /* ---------------------------
           1. Create Runtime
        --------------------------- */

        const app = new global.BoraRuntime(CONFIG);
        global.__BORA_APP__ = app;

        if(CONFIG.dev){
            console.log('[Bootstrap] Runtime created');
        }

        /* ---------------------------
           2. Start Runtime (sync core)
        --------------------------- */

        app.start();
        

        if(CONFIG.dev){
            console.log('[Bootstrap] Runtime started');
        }

        /* =========================================================
        2. CORE SERVICES
        ========================================================== */

        const navigation   = await app.service('navigation');
        const navigator   = await app.service('navigator');
        const hooksService = await app.service('hooks');
        const deprecations = await app.service('deprecations');


        /* =========================================================
        3. SAFE GLOBAL FACADE (Minimal Public API)
        ========================================================== */

        // global.Bora = Object.freeze({
        //     navigate: navigation?.go,
        //     reload:   navigation?.reload,
        //     back:     navigation?.back,
        //     logout:   () => app.plugin('app.core')?.logout()
        // });

        global.Bora = Object.freeze({

            async navigate(...args){
                const nav = await __BORA_APP__?.service('navigation');
                return nav?.go?.(...args);
            },

            async reload(){
                const nav = await __BORA_APP__?.service('navigation');
                return nav?.reload?.();
            },

            async back(){
                const nav = await __BORA_APP__?.service('navigation');
                return nav?.back?.();
            },

            async logout(){
                const core = await __BORA_APP__?.plugin('app.core');
                return core?.logout?.();
            }

        });

        //
        const hooks = await app.service('hooks');

        $(document).on('keyup', (e)=>{
            if(e.key === 'Escape'){
                hooks.call('esc');
                app.emit('esc');
            }
        });


        /* ---------------------------
           3. Preload Core (optional)
        --------------------------- */

        try{

            if(global.__BORA_LOADER__ && CORE_PRELOAD.length){

                if(CONFIG.dev){
                    console.log('[Bootstrap] Preloading core:', CORE_PRELOAD);
                }

                await global.__BORA_LOADER__.preload(CORE_PRELOAD);
            }

        }catch(err){
            console.error('[Bootstrap] Core preload failed', err);
        }

        /* ---------------------------
           4. Initial Route Activation
        --------------------------- */

        async function handleRouteState(app){
            if (restoring) return;
            restoring = true;
            // const navigator = await __BORA_APP__?.service('navigator');

            const url = new URL(window.location);

            const route   = url.searchParams.get('route');
            const surface = url.searchParams.get('surface');

            if (!route) return;

            const params = Object.fromEntries(url.searchParams.entries());

            restoring = false;
            // alert('handle route state '+route);
            return navigator.go({
                route,
                params,
                surface: surface || 'page'
            });
        }

        try{

            const route = normalizeUrl(window.location);
            
            // trigger plugin activation cycle
            await app.emit('route:init', route);

            // also force evaluation directly (safety)
            // if(typeof app.evaluatePluginActivation === 'function'){
            //     await app.evaluatePluginActivation(route);
            // } 

        }catch(err){
            console.error('[Bootstrap] Route init failed', err);
        }

        /* =========================================================
        4. LEGACY EXPOSURE HELPER (Bootstrap-only)
        ========================================================== */

        function exposeLegacy(name, value, resolver){

            let warned = false;

            global[name] = new Proxy({}, {

                get(_, prop){

                    if(!warned && CONFIG.dev && deprecations){
                        warned = true;
                        deprecations.warn(
                            name,
                            `${name} is deprecated. Use runtime services/plugins instead.`
                        );
                    }

                    return async (...args) => {

                        let target = value;

                        if(!target && resolver){
                            target = await resolver();
                        }

                        if(!target){
                            console.error(`[Legacy] ${name} not available`);
                            return;
                        }

                        const fn = target[prop];

                        if(typeof fn !== 'function'){
                            return fn;
                        }

                        return fn.apply(target, args);
                    };
                }
            });
        }

        /* =========================================================
        5. BACKWARD COMPATIBILITY — HOOKS
        ========================================================== */

        exposeLegacy(
            'appHooks',
            null,
            async () => {
                const hooks = await __BORA_APP__?.service('hooks');

                if(!hooks) return null;

                return {
                    addHook: hooks.add?.bind(hooks),
                    removeHook: hooks.remove?.bind(hooks),
                    callHook: hooks.call?.bind(hooks),
                    callHookAsync: hooks.callAsync?.bind(hooks),
                    hasHook: hooks.has?.bind(hooks),
                    getHooks: hooks.get?.bind(hooks),
                    clearHook: hooks.clear?.bind(hooks)
                };
            }
        );
        // if (hooksService) {

        //     let warned = false;

        //     global.appHooks = Object.freeze({

        //         addHook(name, fn, priority){
        //             if(CONFIG.dev && deprecations && !warned){
        //                 warned = true;
        //                 deprecations.warn(
        //                     'appHooks',
        //                     'appHooks is deprecated. Use scope.getService("hooks") instead.'
        //                 );
        //             }
        //             return hooksService.add(name, fn, priority);
        //         },

        //         removeHook(name, fn){
        //             return hooksService.remove(name, fn);
        //         },

        //         callHook(name, ...params){
        //             return hooksService.call(name, ...params);
        //         },

        //         callHookAsync(name, ...params){
        //             return hooksService.callAsync(name, ...params);
        //         },

        //         hasHook(name){
        //             return hooksService.has(name);
        //         },

        //         getHooks(name){
        //             return hooksService.get(name);
        //         },

        //         clearHook(name){
        //             return hooksService.clear(name);
        //         }
        //     });
        // }

        /* =========================================================
        6. LEGACY PLUGIN ALIASES
        ========================================================== */

        // const alerts = await app.plugin('alerts');
        // exposeLegacy('alertBora', alerts);
        // exposeLegacy('alertBoraV2', alerts);
        exposeLegacy(
            'alertBora',
            null,
            () => __BORA_APP__?.plugin('alerts')
        );

        exposeLegacy(
            'BoraPopup',
            null,
            async () => {
                const plugin = await __BORA_APP__?.plugin('popup');
                return plugin?.create ? plugin.create.bind(plugin) : null;
            }
        );

        // console.log(app.plugins);
        // console.log(app.plugin('alerts'));
        // const eventsPlugin = await app.plugin('events');
        // exposeLegacy('BoraEvents', eventsPlugin);
        // eventsPlugin.init();

        exposeLegacy(
            'BoraEvents',
            null,
            () => __BORA_APP__?.plugin('events')
        );

        const uiActions = await app.service('ui.actions');
        uiActions?.init();

        uiActions.register('logout', async() => {
            const alerts = await app.getPlugin('alerts');

            alerts.confirm('Are you <em>really</em> sure?', {
                    html: true
            }).autoCancel(20)
            .then(function() {
                // Allow change, but override flow
                setTimeout(async () => {
                    const appcore = await app.plugin('app.core');
                    appcore.logout();
                }, 0);
            }, function() {
                logTest('Confirmation canceled');
            });
        });


        // const overlayLoader = await app.plugin('overlay');
        exposeLegacy(
            'overlayLoader',
            null,
            () => __BORA_APP__?.plugin('overlay')
        );
        // if(overlayLoader){
            // overlayLoader.show('Saving data...');
            // overlayLoader.setProgress(60);
            // overlay.hide();
        // }


        /* =========================================================
        7. SERVICE BOOTSTRAP
        ========================================================== */

        const prefs = await app.service('preferences');
        prefs?.load();
        console.log('Prefs here...');

        /* =========================================================
        8. CLEAN BUILD SURFACE
        ========================================================== */

        // delete global.__BORA_REGISTER_PLUGIN__;
        // delete global.__BORA_REGISTER_SERVICE__;
        // global.__BORA_REGISTER_PLUGIN__ = function(){
        //     console.error('Plugin registration locked.');
        // };

        // global.__BORA_REGISTER_SERVICE__ = function(){
        //     console.error('Service registration locked.');
        // };


        //Sanity checks
        if(CONFIG.dev){

            const sanity = await app.service('sanity');

            if(sanity){
                const result = sanity.run();

                if(!result.ok){
                    console.error('Bora Runtime Sanity Failed:', result.issues);
                } else {
                    console.log('%c Bora Runtime Sanity OK', 'color:#22c55e');
                }
            }
        }

        const call = await app.service('callbora');

        window.CallBora = function(url){
            return call.builder(url);
        };

        // Old
        window.appUI = window.appUI || {};
        window.appUI.content = {
            async loadPage(url){
                const nav = await window.__BORA_APP__?.service('navigation');
                if(nav){
                    nav.go(url);
                }else{
                    window.location.href = url;
                }
            }
        };

        // Debug force app.actions exposure
        // await __BORA_LOADER__.ensure(
        //     'app.actions'
        // );
        /*
        
        */

        const originalPush = history.pushState;
        const originalReplace = history.replaceState;

        function emitRouteChange(){
            const scope = window.__BORA_APP__?.scope;
            if (!scope) return;

            const url = location.pathname.replace(/^\/+/, '');

            scope.emit('route:changed', {url:url});
        }

        history.pushState = function(){
            originalPush.apply(this, arguments);
            emitRouteChange();
        };

        history.replaceState = function(){
            originalReplace.apply(this, arguments);
            emitRouteChange();
        };

        window.addEventListener('popstate', emitRouteChange);

        /* ---------------------------
           5. Ready Event
        --------------------------- */

        app.emit('app:ready');

        let restoring = false;
        app.on('route:init', () => handleRouteState(app));
        app.on('route:changed', () => handleRouteState(app));
        
        let restoringPopup = false;
        app.on('page.loaded', async () => {

            if (restoringPopup) return;

            const url = new URL(window.location);

            if (url.searchParams.get('surface') !== 'popup') return;

            restoringPopup = true;

            const navigator = await app.service('navigator');

            await navigator.go({
                route: url.searchParams.get('route'),
                params: Object.fromEntries(url.searchParams.entries()),
                surface: 'popup'
            });

            restoringPopup = false;
        });
        // app.on('route:init', async () => {
        //     if (restoring) return;
        //     restoring = true;
        //     const navigator = await app.service('navigator');

        //     const url = new URL(window.location);

        //     const route   = url.searchParams.get('route');
        //     const surface = url.searchParams.get('surface');

        //     if (!route) return;

        //     const params = Object.fromEntries(url.searchParams.entries());

        //     navigator.go({
        //         route,
        //         params,
        //         surface: surface || 'page'
        //     });

        //     restoring = false;
        // });

        // app.on('route:changed', async () => {

        //     const navigator = await app.service('navigator');

        //     const url = new URL(window.location);

        //     const route   = url.searchParams.get('route');
        //     const surface = url.searchParams.get('surface');

        //     if (!route) return;

        //     const params = Object.fromEntries(url.searchParams.entries());

        //     navigator.go({
        //         route,
        //         params,
        //         surface: surface || 'page'
        //     });
        // });

        const total = performance.now() - startTime;

        if(CONFIG.dev){
            console.log(
                `%c Bora App Booted (Lazy Mode) - ${total.toFixed(2)}ms`,
                'color:#22c55e;font-weight:bold;'
            );

            // optional loader debug
            if(global.__BORA_LOADER__?.status){
                console.table(global.__BORA_LOADER__.status());
            }
        }

    }

    /* ==================================================
       UTIL
    ================================================== */

    function normalizeUrl(fullUrl){

        const base = global.__APP_BASE_PATH__ || '';

        if(!fullUrl) return '/';

        fullUrl = String(fullUrl);

        if(base && fullUrl.startsWith(base)){
            fullUrl = fullUrl.slice(base.length);
        }

        fullUrl = fullUrl.split('?')[0];

        return fullUrl || '/';
    }

    /* ==================================================
       SAFE AUTO-START
    ================================================== */

    function ready(fn){
        if(document.readyState === 'complete' || document.readyState === 'interactive'){
            setTimeout(fn, 0);
        }else{
            document.addEventListener('DOMContentLoaded', fn);
        }
    }

    ready(boot);

})(window);