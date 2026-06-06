(function(global){

    'use strict';

    /* ==================================================
       BUILD REGISTRIES (PRE-BOOT)
    ================================================== */

    const pendingPlugins  = new Map();
    const pendingServices = new Map();
    const registrationWaiters = new Map();

    function notifyRegisteredO(name){

        name = name.toLowerCase();

        const waiter = registrationWaiters.get(name);

        if(waiter){
            waiter();
            registrationWaiters.delete(name);
        }
    }

    function notifyRegistered(name){

        name = name.toLowerCase();

        const waiters =
            registrationWaiters.get(name);

        if(!waiters){
            return;
        }

        // legacy single-function waiter
        if(typeof waiters === 'function'){

            waiters();

        }

        // modern array waiters
        else if(Array.isArray(waiters)){

            for(const resolve of waiters){

                try{
                    resolve();
                }
                catch(err){
                    console.error(
                        '[Waiter resolve failed]',
                        name,
                        err
                    );
                }

            }

        }

        registrationWaiters.delete(name);

    }

    function registerPluginDuringBuild(name, factory, meta = {}){
        name = name.toLowerCase();

        pendingPlugins.set(name, { factory, meta });

        if(global.__BORA_APP__?.isStarted()){
            global.__BORA_APP__._registerPlugin(name, factory, meta);
            //
            //global.__BORA_APP__?.integratePending();
        }

        // global.__BORA_APP__?.integratePending();
        //replace direct integration with notification to avoid multiple integrations during build
        scheduleIntegration();
    }

    let integrationScheduled = false;

    function scheduleIntegration(){

        if(integrationScheduled) return;

        integrationScheduled = true;

        queueMicrotask(async ()=>{

            integrationScheduled = false;

            await global.__BORA_APP__?.integratePending();

        });
    }

    function registerServiceDuringBuild(name, factory, meta = {}){
        name = name.toLowerCase();

        pendingServices.set(name, { factory, meta });

        if(global.__BORA_APP__?.isStarted()){
            global.__BORA_APP__._registerService(name, factory, meta);
        }

        scheduleIntegration();
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
            'page.loaded',
            'view:mounted'
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

        function bindDom(selector){
            let $el = null;

            on('view:mounted', ({root}) => {
                const found = $(root).find(selector);

                if(found.length){
                    $el = found;
                }
            });

            return function(){
                if(!$el || !$el.length){
                    $el = $(selector); // fallback
                }
                return $el;
            };
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
                getPluginsByPrefix: async (prefix) => {

                    prefix = prefix.toLowerCase();

                    const results = [];

                    for (const [name, instance] of plugins.entries()){
                        if(name.startsWith(prefix)){
                            results.push({
                                name,
                                instance,
                                meta: pluginMeta.get(name) || {}
                            });
                        }
                    }

                    return results;
                },
                on,
                off,
                emit,
                bindDom,
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

        function useService(name){
            name = name.toLowerCase();
            return services.get(name) || null;
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
                notifyRegistered(name);
            }
            catch(err){
                console.error('[Service failed]', name, err);
            }
        }

        async function _registerPlugin(name, factory, meta = {}){
            // console.log(
            //     '[REGISTER PLUGIN]',
            //     name
            // );
            name = name.toLowerCase();

            if(plugins.has(name)){
                console.warn('[Plugin exists]', name);
                return;
            }
            

            try{
                const instance = await factory(createScope());

                plugins.set(name, instance);
                pluginMeta.set(name, meta);
                notifyRegistered(name);

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
        let integrating = false;
        let integrateAgain = false;

        async function integratePending(){

            if(integrating){
                integrateAgain = true;
                return;
            }

            integrating = true;

            try{
                do {
                    integrateAgain = false;

                    if(!started) break;

                    // services
                    // pendingServices.forEach(({factory, meta}, name)=>{
                    //     name = name.toLowerCase();
                    //     if(!services.has(name)){
                    //         await _registerService(name, factory, meta);
                    //     }
                    // });

                    const serviceBatch = [...pendingServices.entries()];

                    pendingServices.clear();    

                    for(const [name, {factory, meta}] of serviceBatch){

                        const normalized = name.toLowerCase();

                        if(!services.has(normalized)){
                            await _registerService(normalized, factory, meta);
                        }

                    }

                    // pendingServices.clear();

                    // plugins
                    let newPlugins = false;

                    // pendingPlugins.forEach(({factory, meta}, name)=>{
                    //     name = name.toLowerCase();
                    //     if(!plugins.has(name)){
                    //         await _registerPlugin(name, factory, meta);
                    //          newPlugins = true;
                    //     }
                    // });

                    // for(const [name, {factory, meta}] of pendingPlugins){

                    //     const normalized = name.toLowerCase();

                    //     if(!plugins.has(normalized)){
                    //         await _registerPlugin(normalized, factory, meta);
                    //     }

                    // }

                    // for(const [name, {factory, meta}] of pendingPlugins){

                    //     const normalized = name.toLowerCase();

                    //     if(!plugins.has(normalized)){

                    //         await _registerPlugin(
                    //             normalized,
                    //             factory,
                    //             meta
                    //         );

                    //         newPlugins = true;

                    //     }

                    // }

                    // pendingPlugins.clear();

                    const pluginBatch = [...pendingPlugins.entries()];

                    pendingPlugins.clear();

                    for(const [name, {factory, meta}] of pluginBatch){

                        const normalized = name.toLowerCase();

                        if(!plugins.has(normalized)){

                            await _registerPlugin(
                                normalized,
                                factory,
                                meta
                            );

                            newPlugins = true;

                        }

                    }

                    // 🔥 CRITICAL: trigger activation only if new plugins arrived
                    if(newPlugins){
                        console.log('NEW PLUGINS:: ', newPlugins);
                        await evaluatePluginActivation(normalizeUrl(window.location));
                    }

                    
                }
                while(integrateAgain);
            }
            finally{
                integrating = false;
            }
        }

        function resolveFace(path){

            path = normalizeUrl(path);

            if(path === 'portal' || path.startsWith('portal/')){
                return 'client';
            }

            if(path === 'bo' || path.startsWith('bo/')){
                return 'admin';
            }

            return 'guest';
        }

        function getFace(){
            return global.__BORA_FACE__ || resolveFace(normalizeUrl(window.location));
        }

        async function syncFace(face){

            global.__BORA_FACE__ = face;

            try{

                const context = services.get('context');

                if(context){
                    context.set(face);
                }

            }catch(err){
                console.warn('[Face sync failed]', err);
            }
        }


        /* ==================================================
           ACTIVATION (LAZY SAFE)
        ================================================== */
        let cn = 0;
        async function evaluatePluginActivation(route){
            // alert('evaluatePluginActivation :: ' + route + ' called:: '+cn); cn++;
            const manifest = rd('manifest');// || global.__BORA_MANIFEST__ || {};
            console.warn('[MANIFEST]', manifest);

            global.__BORA_FACE__ = resolveFace(route);
            await syncFace(global.__BORA_FACE__);
           
            if(config.dev){
                console.log(`[Runtime] evaluatePluginActivation for face: ${global.__BORA_FACE__}`);
            }

            // alert(global.__BORA_FACE__ + ' route: ' + route);
        
            const context = {
                route,
                face: global.__BORA_FACE__ || 'guest', // default to guest if face service or resolution fails
                appcore: plugins.get('app.core'),
                plugins
            };

            /* ---------------------------
            SORT (priority-aware)
            --------------------------- */

            const pluginNames = Object.keys(manifest)
                .filter(name => manifest[name].type === 'plugin')
                .sort((a, b) => {
                    const pa = manifest[a]?.priority || 0;
                    const pb = manifest[b]?.priority || 0;
                    return pb - pa; // higher first
                });


            if(config.dev){
                console.warn('[Sorted plugins]', pluginNames);
            }

            /* ---------------------------
            LOOP
            --------------------------- */
            let cnt = 0;
            for(const name of pluginNames){
                // alert('Load name:: '+name);
                const meta = manifest[name];

                // 🧠 Phase 1: should load?
                if(!shouldLoad(meta, context)){
                    continue;
                }

                // console.warn(`[Loader-success] Loading plugin: ${name}`);
                // ensure code is loaded
                await global.__BORA_LOADER__.ensure(name, {
                    activate:false
                });

                const plugin = plugins.get(name);
                // console.warn(`[Loader]-helper Plugin "${name}" loaded:`, plugin);
                // Plugin not loaded yet (loader should have loaded it by now, but just in case)
                if(!plugin){
                    // console.error(`[Loader] Plugin "${name}" is not loaded yet.`);
                    // console.log(pluginMeta.get(name));
                    continue;
                }

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
                    // alert('Plugin:: '+name+ ' cnt:: '+cnt); cnt++;
                    if(!plugin.__active){

                        try{
                            const start = performance.now();

                            await plugin.mount?.();
                            plugin.__active = true;

                            // console.log(
                            //     `%c ${name} Plugin active`,
                            //     'color:#22c55e;font-weight:bold;'
                            // );

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

        function shouldLoad(meta, context){
            // console.log('[Should Load?]', meta, context);

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
                    // console.log(`activateOn:: ${name} for ${route}`);
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
                // console.warn('[Runtime already started]');
                return;
            }

            started = true;

            emit('runtime:beforeStart');

            // inject jquery if already present
            if(global.jQuery){
                services.set('jquery', global.jQuery);
            }

            //detect face (important for initial route activation)
            if(!global.__BORA_FACE__){
                global.__BORA_FACE__ = resolveFace(normalizeUrl(window.location));
                if(config.dev){
                    console.log(`[Runtime] Detected face: ${global.__BORA_FACE__}`);
                }
            }
            
            // register pending services
            for(const [name, {factory, meta}] of pendingServices){

                const normalized = name.toLowerCase();

                if(!services.has(normalized)){
                    await _registerService(normalized, factory, meta);
                }

            }

            emit('runtime:servicesReady');

            // register pending plugins (only already loaded ones)
            for(const [name, {factory, meta}] of pendingPlugins){

                const normalized = name.toLowerCase();

                if(!plugins.has(normalized)){
                    await _registerPlugin(normalized, factory, meta);
                }

            }


            emit('runtime:started');

            // initial activation (lazy)
            await evaluatePluginActivation(normalizeUrl(window.location));
            
            emit('page.loaded', {
                source: 'initial',
                url: window.location
            });

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

        function currentRoute(){
            return normalizeUrl(window.location);
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

            bindDom,

            // Internal (used for late module load)
            _registerPlugin,
            _registerService,
            evaluatePluginActivation,
            _registrationWaiters: registrationWaiters,
            face: getFace,
            currentRoute: () => normalizeUrl(window.location),
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