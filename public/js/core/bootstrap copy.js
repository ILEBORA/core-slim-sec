(function (global) {

    /* =========================================================
       1. CONFIG + RUNTIME
    ========================================================== */

    const config = global.__BORA_CONFIG__ || {
        dev: true,
        securityMode: 'strict'
    };

    const app = BoraRuntime(config);
    global.__BORA_APP__ = app;

    app.start();

    const faceService = app.service('face');
    const face = faceService.current();

    // if(face === 'guest')  app.plugin('GuestFace')?.mount();
    // if(face === 'client') app.plugin('ClientFace')?.mount();
    // if(face === 'admin')  app.plugin('AdminFace')?.mount();

    // let currentFace = face;

    // app.service('state').subscribe('route', (newRoute)=>{

    //     const newFace = faceService.resolve(newRoute);

    //     if(newFace === currentFace) return;

    //     // Unmount old
    //     if(currentFace === 'guest')  app.plugin('GuestFace')?.unmount?.();
    //     if(currentFace === 'client') app.plugin('ClientFace')?.unmount?.();
    //     if(currentFace === 'admin')  app.plugin('AdminFace')?.unmount?.();

    //     // Mount new
    //     if(newFace === 'guest')  app.plugin('GuestFace')?.mount();
    //     if(newFace === 'client') app.plugin('ClientFace')?.mount();
    //     if(newFace === 'admin')  app.plugin('AdminFace')?.mount();

    //     currentFace = newFace;
    // });
    

    /* =========================================================
       2. CORE SERVICES
    ========================================================== */

    const navigation   = app.service('navigation');
    const hooksService = app.service('hooks');
    const deprecations = app.service('deprecations');


    /* =========================================================
       3. SAFE GLOBAL FACADE (Minimal Public API)
    ========================================================== */

    global.Bora = Object.freeze({
        navigate: navigation?.go,
        reload:   navigation?.reload,
        back:     navigation?.back,
        logout:   () => app.plugin('AppCore')?.logout()
    });

    //
    const hooks = app.service('hooks');

    $(document).on('keyup', (e)=>{
        if(e.key === 'Escape'){
            hooks.call('esc');
            app.emit('esc');
        }
    });

    /* =========================================================
       4. LEGACY EXPOSURE HELPER (Bootstrap-only)
    ========================================================== */

    function exposeLegacy(name, value){

        if(!value) return;

        let warned = false;

        global[name] = new Proxy(value, {
            get(target, prop){

                if(!warned && config.dev && deprecations){
                    warned = true;
                    deprecations.warn(
                        name,
                        `${name} is deprecated. Use runtime services/plugins instead.`
                    );
                }

                return target[prop];
            }
        });
    }


    /* =========================================================
       5. BACKWARD COMPATIBILITY — HOOKS
    ========================================================== */

    if (hooksService) {

        let warned = false;

        global.appHooks = Object.freeze({

            addHook(name, fn, priority){
                if(config.dev && deprecations && !warned){
                    warned = true;
                    deprecations.warn(
                        'appHooks',
                        'appHooks is deprecated. Use scope.getService("hooks") instead.'
                    );
                }
                return hooksService.add(name, fn, priority);
            },

            removeHook(name, fn){
                return hooksService.remove(name, fn);
            },

            callHook(name, ...params){
                return hooksService.call(name, ...params);
            },

            callHookAsync(name, ...params){
                return hooksService.callAsync(name, ...params);
            },

            hasHook(name){
                return hooksService.has(name);
            },

            getHooks(name){
                return hooksService.get(name);
            },

            clearHook(name){
                return hooksService.clear(name);
            }
        });
    }


    /* =========================================================
       6. LEGACY PLUGIN ALIASES
    ========================================================== */

    const alerts = app.plugin('alerts');
    exposeLegacy('alertBora', alerts);
    exposeLegacy('alertBoraV2', alerts);

    const popupPlugin = app.plugin('popup');
    if (popupPlugin?.create) {
        exposeLegacy('BoraPopup', popupPlugin.create);
    }

    // console.log(app.plugins);
    // console.log(app.plugin('alerts'));
    const eventsPlugin = app.plugin('events');
    exposeLegacy('BoraEvents', eventsPlugin);
    eventsPlugin.init();

    const uiActions = app.service('ui.actions');
    uiActions?.init();

    uiActions.register('logout', () => {
        app.plugin('AppCore')?.logout();
    });


    const overlayLoader = app.plugin('Overlay');
    // if(overlayLoader){
        // overlayLoader.show('Saving data...');
        // overlayLoader.setProgress(60);
        // overlay.hide();
    // }


    /* =========================================================
       7. SERVICE BOOTSTRAP
    ========================================================== */

    const prefs = app.service('preferences');
    prefs?.load();


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
    if(config.dev){

        const sanity = app.service('sanity');

        if(sanity){
            const result = sanity.run();

            if(!result.ok){
                console.error('Bora Runtime Sanity Failed:', result.issues);
            } else {
                console.log('%c Bora Runtime Sanity OK', 'color:#22c55e');
            }
        }
    }

    const call = app.service('callbora');

    window.CallBora = function(url){
        return call.builder(url);
    };

    // Old
    window.appUI = window.appUI || {};
    window.appUI.content = {
        loadPage(url){
            const nav = window.__BORA_APP__?.service('navigation');
            if(nav){
                nav.go(url);
            }else{
                window.location.href = url;
            }
        }
    };

    /* =========================================================
       9. READY SIGNAL
    ========================================================== */

    if(typeof app.emit === 'function'){
        app.emit('runtime:ready');
    }

    
})(window);