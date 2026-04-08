(function(global){

    'use strict';

    /* ==================================================
       BUILD REGISTRIES (PRE-BOOT)
    ================================================== */

    const pendingPlugins  = new Map();
    const pendingServices = new Map();

    function registerPluginDuringBuild(name, factory, meta = {}){
        name = name.toLowerCase();

        pendingPlugins.set(name, { factory, meta });

        if(global.__BORA_APP__?.isStarted()){
            global.__BORA_APP__._registerPlugin(name, factory, meta);
            //
            //global.__BORA_APP__?.integratePending();
        }

        global.__BORA_APP__?.integratePending();
    }

    function registerServiceDuringBuild(name, factory, meta = {}){
        name = name.toLowerCase();

        pendingServices.set(name, { factory, meta });

        if(global.__BORA_APP__?.isStarted()){
            global.__BORA_APP__._registerService(name, factory, meta);
        }
    }

    /* ==================================================
       RUNTIME
    ================================================== */

    function BoraRuntime(config = {}){

        const services   = new Map();
        const plugins    = new Map();
        const pluginMeta = new Map();

        // const events  = new Map();
        const timings = new Map();
        const errors  = new Map();

        const firedEvents = new Map();

        let started = false;

        if(config.dev){
            global.__BORA_DEBUG__ = {
                plugins,
                meta: pluginMeta,
                eval: evaluatePluginActivation
            };
        }

        /* ==================================================
        EVENT BUS (STATEFUL + REPLAYABLE)
        ================================================== */

        const events = new Map();        // event => [handlers]
        const fired = new Map();         // event => last payload
        const replayable = new Set([
            'runtime:started',
            'page.loaded'
        ]);

        function on(event, handler, options = {}){
            if(!events.has(event)) events.set(event, []);
            
            const handlers = events.get(event);
            handlers.push(handler);

            // 🔥 Immediate replay if already fired
            if(
                replayable.has(event) &&
                fired.has(event) &&
                options.replay !== false // allow opt-out
            ){
                try{
                    handler(fired.get(event));
                }
                catch(err){
                    console.error('[Runtime event replay error]', err);
                }
            }

            // return unsubscribe (very useful)
            return () => off(event, handler);
        }

        function off(event, handler){
            if(!event){
                events.clear();
                fired.clear(); // important: reset state too
                return;
            }

            const handlers = events.get(event);
            if(!handlers) return;

            if(!handler){
                events.delete(event);
                fired.delete(event);
                return;
            }

            const index = handlers.indexOf(handler);
            if(index !== -1){
                handlers.splice(index, 1);
            }

            if(handlers.length === 0){
                events.delete(event);
            }
        }

        function emit(event, payload){
            // store state if replayable
            if(replayable.has(event)){
                fired.set(event, payload);
            }

            const handlers = events.get(event);
            if(!handlers) return;

            // clone to avoid mutation issues during emit
            [...handlers].forEach(fn=>{
                try{
                    fn(payload);
                }
                catch(err){
                    console.error('[Runtime event error]', err);
                }
            });
        }

        /* ==================================================
           SCOPE
        ================================================== */

        function createScope(){
            return Object.freeze({
                getService,
                getPlugin,
                hasService: (n)=>services.has(n),
                hasPlugin: (n)=>plugins.has(n),
                on,
                off,
                emit,
                config,
                runtimeInstance: publicAPI,
                evaluatePluginActivation
            });
        }

        /* ==================================================
           ASYNC ACCESS (CORE CHANGE)
        ================================================== */

        async function getService(name){
            name = name.toLowerCase();
            if(!services.has(name)){
                await global.__BORA_LOADER__?.ensure(name);
            }

            return services.get(name);
        }

        async function getPlugin(name){
            name = name.toLowerCase();
            if(!plugins.has(name)){
                await global.__BORA_LOADER__?.ensure(name);
            }

            return plugins.get(name);
        }

        /* ==================================================
           INTERNAL REGISTRATION
        ================================================== */

        async function _registerService(name, factory, meta = {}){
            name = name.toLowerCase();

            if(services.has(name)){
                console.warn('[Service exists]', name);
                return;
            }

            try{
                const instance = await factory(createScope());
                services.set(name, instance);
            }
            catch(err){
                console.error('[Service failed]', name, err);
            }
        }

        async function _registerPlugin(name, factory, meta = {}){
            name = name.toLowerCase();

            if(plugins.has(name)){
                console.warn('[Plugin exists]', name);
                return;
            }

            try{
                const instance = await factory(createScope());

                plugins.set(name, instance);
                pluginMeta.set(name, meta);

                // lazy-safe activation trigger
                // await evaluatePluginActivation(normalizeUrl(window.location));

            }
            catch(err){
                errors.set(name, err);
                console.error('[Plugin crashed]', name, err);
            }
        }

        /* ==================================================
           INTEGRATION (LOADER HOOK)
        ================================================== */

        async function integratePending(){

            if(!started) return;

            // services
            pendingServices.forEach(({factory, meta}, name)=>{
                name = name.toLowerCase();
                if(!services.has(name)){
                    _registerService(name, factory, meta);
                }
            });

            pendingServices.clear();

            // plugins
            let newPlugins = false;

            pendingPlugins.forEach(({factory, meta}, name)=>{
                name = name.toLowerCase();
                if(!plugins.has(name)){
                    _registerPlugin(name, factory, meta);
                     newPlugins = true;
                }
            });

            pendingPlugins.clear();

            // 🔥 CRITICAL: trigger activation only if new plugins arrived
            if(newPlugins){
                console.log('NEW PLUGINS:: ', newPlugins);
                await evaluatePluginActivation(normalizeUrl(window.location));
            }
        }

        /* ==================================================
           ACTIVATION (LAZY SAFE)
        ================================================== */

        async function evaluatePluginActivation(route){

            const manifest = global.__BORA_MANIFEST__ || {};

            const context = {
                route,
                face: global.__BORA_FACE__ || 'guest',
                appcore: plugins.get('appcore'),
                plugins
            };

            /* ---------------------------
            SORT (priority-aware)
            --------------------------- */

            const pluginNames = Object.keys(manifest)
                .filter(name => manifest[name].type === 'plugin')
                .sort((a, b) => {
                    const pa = pluginMeta.get(a)?.priority || 0;
                    const pb = pluginMeta.get(b)?.priority || 0;
                    return pb - pa; // higher first
                });

            /* ---------------------------
            LOOP
            --------------------------- */

            for(const name of pluginNames){

                const meta = manifest[name];

                // 🧠 Phase 1: should load?
                if(!shouldLoad(meta, context)){
                    continue;
                }

                // ensure code is loaded
                await global.__BORA_LOADER__.ensure(name);

                const plugin = plugins.get(name);
                if(!plugin) continue;

                const pMeta = pluginMeta.get(name);

                const shouldActivate = evaluateMeta(name, pMeta, context);

                /* ---------------------------
                DEBUG (optional but useful)
                --------------------------- */

                if(config.dev){
                    console.log(`[Activation] ${name}`, {
                        route,
                        active: shouldActivate
                    });
                }

                /* ---------------------------
                MOUNT
                --------------------------- */

                if(shouldActivate){

                    if(!plugin.__active){

                        try{
                            const start = performance.now();

                            await plugin.mount?.();
                            plugin.__active = true;

                            console.log(
                                `%c ${name} Plugin active`,
                                'color:#22c55e;font-weight:bold;'
                            );

                            /* timing (optional keep your existing logic) */

                        }catch(err){
                            errors.set(name, err);
                            emit('plugin:error', { name, error: err });
                        }
                    }

                }else{

                    /* ---------------------------
                    UNMOUNT
                    --------------------------- */

                    if(plugin.__active){

                        try{
                            await plugin.unmount?.();
                            plugin.__active = false;

                            console.log(
                                `%c ${name} Plugin unmounted`,
                                'color:red;font-weight:bold;'
                            );

                        }catch(err){
                            console.error(`[Plugin] Unmount failed: ${name}`, err);
                        }
                    }
                }
            }
        }

        // async function evaluatePluginActivationO(route){
            
        //     const manifest = global.__BORA_MANIFEST__ || {};
        //     console.log('MANIFEST::', manifest);
        //     for(const name in manifest){
                
        //         const meta = manifest[name];

        //         // only plugins
        //         if(meta.type !== 'plugin') continue;
                
        //         // ensure plugin is loaded first
        //         await global.__BORA_LOADER__.ensure(name);
        //         // console.log('check:: '+ name);
        //         // console.log('Plugins:: ', plugins);
        //         // console.log('Service::',services);
        //         const plugin = plugins.get(name);
        //         if(!plugin) continue;

        //         // console.log('here with '+ name);
        //         // console.log(plugin);
        //         /* ---------------------------
        //         ACTIVATION DECISION (runtime-owned)
        //         --------------------------- */

        //         // let shouldActivate = true;

        //         const pMeta = pluginMeta.get(name);

        //         const shouldActivate = evaluateMeta(pMeta, {
        //             route,
        //             face: global.__BORA_FACE__ || 'guest',
        //             appcore: plugins.get('appcore')
        //         });

        //         /* ---------------------------
        //         MOUNT / UNMOUNT
        //         --------------------------- */

        //         if(shouldActivate){

        //             if(!plugin.__active){

        //                 try{
        //                     const start = performance.now();

        //                     await plugin.mount?.();
        //                     plugin.__active = true;

        //                     console.log(
        //                         `%c ${name} Plugin active or mounted`,
        //                         'color:#22c55e;font-weight:bold;'
        //                     );

        //                     if(config.dev){
        //                         const ms = performance.now() - start;

        //                         const existing = timings.get(name);

        //                         if(typeof existing === 'number'){
        //                             timings.set(name, { count: 1, total: existing, avg: existing, max: existing });
        //                         }

        //                         if(existing){
        //                             const newTotal = existing.total + ms;
        //                             const newCount = existing.count + 1;

        //                             timings.set(name, {
        //                                 count: newCount,
        //                                 total: newTotal,
        //                                 avg: newTotal / newCount,
        //                                 max: Math.max(existing.max, ms)
        //                             });
        //                         }else{
        //                             timings.set(name, {
        //                                 count: 1,
        //                                 total: ms,
        //                                 avg: ms,
        //                                 max: ms
        //                             });
        //                         }

        //                         emit('plugin:timing', { name });

        //                         if(ms > 20){
        //                             console.warn(`[Slow mount] ${name}: ${ms.toFixed(2)}ms`);
        //                         }
        //                     }

        //                 }catch(err){
        //                     errors.set(name, err);
        //                     emit('plugin:error', { name, error: err });
        //                 }
        //             }

        //         }else{

        //             // 🔥 IMPORTANT: handle unmount
        //             if(plugin.__active){

        //                 try{
        //                     await plugin.unmount?.();
        //                     plugin.__active = false;

        //                     console.log(`%c ${name} Plugin unmounted`, 'color:red;font-weight:bold;');
        //                 }catch(err){
        //                     console.error(`[Plugin] Unmount failed: ${name}`, err);
        //                 }

        //             }
        //         }
        //     }
        // }
        function shouldLoad(meta, context){

            if(!meta) return true;

            const { route, face } = context;

            if(Array.isArray(meta.faces)){
                if(!meta.faces.includes(face)) return false;
            }

            if(typeof meta.activateOn === 'function'){
                try{
                    if(meta.activateOn(route) !== true){
                        return false;
                    }
                }catch(e){
                    return false;
                }
            }

            return true;
        }

        function evaluateMeta(name, pMeta, context){

            if(!pMeta) return true;

            const {
                route,
                face,
                appcore,
                plugins
            } = context;

            /* ---------------------------
            FACE
            --------------------------- */

            if(Array.isArray(pMeta.faces)){
                if(!pMeta.faces.includes(face)){
                    return false;
                }
            }

            /* ---------------------------
            PERMISSIONS
            --------------------------- */

            if(typeof pMeta.permissions === 'function'){
                try{
                    if(pMeta.permissions(appcore) !== true){
                        return false;
                    }
                }catch(e){
                    console.error(`[Plugin] permission check failed for ${name}`, e);
                    return false;
                }
            }

            /* ---------------------------
            DEPENDS ON (runtime-level)
            --------------------------- */

            if(Array.isArray(pMeta.dependsOn)){
                for(const dep of pMeta.dependsOn){
                    const p = plugins.get(dep);
                    if(!p || p.__active !== true){
                        return false;
                    }
                }
            }

            /* ---------------------------
            ROUTE
            --------------------------- */

            if(typeof pMeta.activateOn === 'function'){
                try{
                    console.log(`activateOn:: ${name} for ${route}`);
                    if(pMeta.activateOn(route) !== true){
                        return false;
                    }
                }catch(e){
                    console.error(`[Plugin] activateOn failed for ${name}`, e);
                    return false;
                }
            }

            return true;
        }

        // async function evaluatePluginActivationO(route){

        //     const manifest = global.__BORA_MANIFEST__ || {};

        //     for(const name in manifest){

        //         const meta = manifest[name];

        //         // only plugins
        //         if(!meta.file || !meta.file.includes('plugins/')) continue;

        //         // default OFF
        //         let shouldActivate = true;

        //         // if(meta.activateOn){
        //         //     alert(`Should Activate ${name} ` + meta.activateOn(route));
        //         //     shouldActivate = meta.activateOn(route);
        //         // }
        //         /* ---------------------------
        //         ACTIVATION DECISION (runtime-owned)
        //         --------------------------- */
        //         if(typeof plugin.activateOn === 'function'){
        //             try{
        //                 shouldActivate = plugin.activateOn(route);
        //             }catch(e){
        //                 console.error(`[Plugin] activateOn failed for ${name}`, e);
        //                 shouldActivate = false;
        //             }
        //         }

        //         if(!shouldActivate) continue;
        //         // console.log(`should mount ${name} `);

        //         await global.__BORA_LOADER__.ensure(name);

        //         const plugin = plugins.get(name);
        //         if(!plugin) continue;

        //         if(!plugin.__active){

        //             try{
        //                 // console.log(`Plugin ${name} found... mounting`,plugin);
        //                 const start = performance.now();
        //                 await plugin.mount?.();
        //                 plugin.__active = true;

        //                 console.log(`${name} Plugin active`);

        //                 if(config.dev){ 
        //                     const ms = performance.now() - start; 
        //                     // timings.set(name, ms); 
        //                     const existing = timings.get(name); 
        //                     if(typeof existing === 'number'){ 
        //                         //migrate old format 
        //                         timings.set(name, { count: 1, total: existing, avg: existing, max: existing }); 
        //                         emit('plugin:timing', { name }); 
        //                     } 
        //                     if(existing){ 
        //                         const newTotal = existing.total + ms; 
        //                         const newCount = existing.count + 1; 
        //                         timings.set(name, { count: newCount, total: newTotal, avg: newTotal / newCount, max: Math.max(existing.max, ms) }); 
        //                         emit('plugin:timing', { name }); 
        //                     }else{ 
        //                         timings.set(name, { count: 1, total: ms, avg: ms, max: ms }); 
        //                         emit('plugin:timing', { name }); 
        //                     } 

        //                     if(ms > 20){ 
        //                         console.warn(`[Slow mount] ${name}: ${ms.toFixed(2)}ms`); 
        //                     }

        //                 }
        //             }
        //             catch(err){
        //                 errors.set(name, err);
        //                 emit('plugin:error', { name, error: err });
        //             }
        //         }
        //     }
        // }

        // async function evaluatePluginActivationO(route){

        //     const manifest = global.__BORA_MANIFEST__ || {};

        //     for(const name in manifest){

        //         const meta = manifest[name];

        //         // only consider plugins
        //         if(!meta.file || !meta.file.includes('plugins/')) continue;

        //         let shouldActivate = false;

        //         if(meta.activateOn){
        //             // shouldActivate = shouldActivate && meta.activateOn(route);
        //             let shouldActivate = true;
        //         }

        //         if(!shouldActivate) continue;

        //         // ensure plugin is loaded
        //         await global.__BORA_LOADER__.ensure(name);

        //         const plugin = plugins.get(name);
        //         if(!plugin) continue;

        //         if(!plugin.__active){

        //             try{
        //                 await plugin.mount?.();
        //                 plugin.__active = true;
        //             }
        //             catch(err){
        //                 errors.set(name, err);
        //                 emit('plugin:error', { name, error: err });
        //             }
        //         }
        //     }
        // }

        function normalizeUrl(fullUrl){
            const base = window.__APP_BASE_PATH__ || '';

            if(!fullUrl) return '/';

            fullUrl = String(fullUrl);

            if(base && fullUrl.startsWith(base)){
                fullUrl = fullUrl.slice(base.length);
            }

            fullUrl = fullUrl.split('?')[0];

            return fullUrl || '';
        }

        /* =========================
           SANITY CHECK
        ========================= */

        function sanity(){

            const issues = [];

            if(!services.has('state')){
                issues.push('Missing state service');
            }

            if(!services.has('navigation')){
                issues.push('Missing navigation service');
            }

            if(!plugins.size){
                issues.push('No plugins mounted');
            }

            return {
                ok: issues.length === 0,
                issues
            };
        }

        /* ==================================================
           START
        ================================================== */

        async function start(){

            if(started){
                console.warn('[Runtime already started]');
                return;
            }

            started = true;

            emit('runtime:beforeStart');

            // inject jquery if already present
            if(global.jQuery){
                services.set('jquery', global.jQuery);
            }

            // register pending services
            pendingServices.forEach(({factory, meta}, name)=>{
                _registerService(name, factory, meta);
            });

            emit('runtime:servicesReady');

            // register pending plugins (only already loaded ones)
            pendingPlugins.forEach(({factory, meta}, name)=>{
                _registerPlugin(name, factory, meta);
            });

            emit('runtime:started');

            
            emit('page.loaded', {
                source: 'initial',
                url: window.location
            });

            // initial activation (lazy)
            // await evaluatePluginActivation(normalizeUrl(window.location));

            Object.freeze(services);
            Object.freeze(plugins);

            // Dev diagnostics
            if(config.dev){

                const report = sanity();

                if(!report.ok){
                    console.error('[BoraRuntime] Sanity failed:', report.issues);
                }
                else{
                    console.log('%c BoraRuntime started (clean)',
                        'color:#22c55e;font-weight:bold;'
                    );
                }

                console.table( 
                    Array.from(timings.entries()).map(([name, t]) => ({ 
                        plugin: name, 
                        mounts: t.count, 
                        avg_ms: t.avg.toFixed(2), 
                        max_ms: t.max.toFixed(2), 
                        total_ms: t.total.toFixed(2) 
                    })) 
                );
            }
        }

        /* ==================================================
           PUBLIC API
        ================================================== */

        const publicAPI = {
            start,

            plugin: getPlugin,
            service: getService,

            // async access
            getService,
            getPlugin,

            // internal
            integratePending,
            isStarted:()=>started,

            // debug / internal
            _registerPlugin,
            _registerService,
            _getServices: ()=>services,
            _getPlugins: ()=>plugins,
            _getMeta: () => pluginMeta, 
            __timings: timings,
            __errors: errors,

            on,
            off,
            emit,

            // Internal (used for late module load)
            _registerPlugin,
            _registerService,
            evaluatePluginActivation
        };

        return Object.freeze(publicAPI);
    }

    /* ==================================================
       EXPORTS
    ================================================== */

    global.BoraRuntime = BoraRuntime;
    global.__BORA_REGISTER_PLUGIN__  = registerPluginDuringBuild;
    global.__BORA_REGISTER_SERVICE__ = registerServiceDuringBuild;

})(window);