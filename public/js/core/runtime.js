(function(global){

    /* ==================================================
       BUILD REGISTRIES
    ================================================== */

    const pendingPlugins  = new Map();
    const pendingServices = new Map();

    function registerPluginDuringBuild(name, factory, meta = {}){
        pendingPlugins.set(name, { factory, meta });

        if(global.__BORA_APP__?.isStarted()){
            global.__BORA_APP__._registerPlugin(name, factory, meta);
        }
    }

    function registerServiceDuringBuild(name, factory, meta = {}){
        pendingServices.set(name, { factory, meta });

        if(global.__BORA_APP__?.isStarted()){
            global.__BORA_APP__._registerService(name, factory, meta);
        }
    }

    /* ==================================================
       RUNTIME
    ================================================== */

    function BoraRuntime(config = {}){

        const services      = new Map();
        const plugins       = new Map();
        const pluginMeta    = new Map();
        const events        = new Map();
        const timings       = new Map();
        const errors        = new Map();

        let started = false;

        /* =========================
           EVENT BUS
        ========================= */

        function on(event, handler){
            if(!events.has(event)) events.set(event, []);
            events.get(event).push(handler);
        }

        function emit(event, payload){

            const handlers = events.get(event);
            if(!handlers) return;

            handlers.forEach(fn=>{
                const start = performance.now();
                try{ fn(payload); }
                catch(err){
                    console.error('[Runtime event error]', err);
                }

                if(config.dev){
                    const ms = performance.now() - start;
                    if(ms > 10){
                        console.warn(`[Slow event] ${event}: ${ms.toFixed(2)}ms`);
                    }
                }
            });
        }

        /* =========================
           SERVICE REGISTRATION
        ========================= */

        function _registerService(name, factory, meta = {}){

            if(services.has(name)){
                console.warn('[Service exists]', name);
                return;
            }

            const requires = meta.requires || [];

            requires.forEach(dep=>{
                if(!services.has(dep)){
                    throw new Error(
                        `Service "${name}" requires missing "${dep}"`
                    );
                }
            });

            try{
                const instance = factory(createScope());
                services.set(name, instance);
            }
            catch(err){
                console.error('[Service failed]', name, err);
            }
        }

        /* =========================
           PLUGIN REGISTRATION
        ========================= */

        function _registerPlugin(name, factory, meta = {}){

            if(plugins.has(name)){
                console.warn('[Plugin exists]', name);
                return;
            }

            try{

                const instance = factory(createScope());

                plugins.set(name, instance);
                pluginMeta.set(name, meta);

                // DO NOT mount here

            }
            catch(err){
                console.error('[Plugin crashed]', name, err);
            }
        }

        function _registerPluginO(name, factory, meta = {}){

            if(plugins.has(name)){
                console.warn('[Plugin exists]', name);
                return;
            }

            try{

                const start = performance.now();

                const instance = factory(createScope());
                plugins.set(name, instance);

                instance?.mount?.();

                if(config.dev){
                    timings.set(name, performance.now() - start);
                }

            }
            catch(err){
                errors.set(name, err);
                emit('plugin:error', { name, error:err });
                console.error('[Plugin crashed]', name, err);
            }
        }

        /* =========================
           SCOPE
        ========================= */

        function createScope(){
            return Object.freeze({
                getService,
                hasService,
                on,
                emit,
                config
            });
        }

        function getService(name){ return services.get(name); }
        function hasService(name){ return services.has(name); }
        function getPlugin(name){ return plugins.get(name); }

        /* =========================
           DEP RESOLUTION
        ========================= */

        function resolvePluginOrder(){

            const resolved = [];
            const unresolved = new Set(pendingPlugins.keys());
            let safety = 0;

            while(unresolved.size && safety < 1000){

                safety++;

                unresolved.forEach(name=>{

                    const { meta } = pendingPlugins.get(name);
                    const requires = meta?.requires || [];

                    const ok = requires.every(dep =>
                        services.has(dep) || resolved.includes(dep)
                    );

                    if(ok){
                        resolved.push(name);
                        unresolved.delete(name);
                    }
                });
            }

            if(unresolved.size){
                console.error('[Unresolved plugins]', Array.from(unresolved));
            }

            return resolved;
        }

        function handlePluginActivationO(route){

            plugins.forEach((instance, name)=>{

                const meta = pluginMeta.get(name);

                if(!meta?.activateOn) return;

                const shouldBeActive = meta.activateOn(route);

                if(shouldBeActive && !instance.__active){
                    instance.mount?.();
                    instance.__active = true;
                }

                if(!shouldBeActive && instance.__active){
                    instance.unmount?.();
                    instance.__active = false;
                }

            });
        }

        function integratePending(){

            if(!started){
                console.warn('Runtime not started yet.');
                return;
            }

            // SERVICES
            pendingServices.forEach(({factory, meta}, name)=>{
                if(!services.has(name)){
                    _registerService(name, factory, meta);
                }
            });

            pendingServices.clear();

            // PLUGINS
            pendingPlugins.forEach(({factory, meta}, name)=>{
                if(!plugins.has(name)){
                    _registerPlugin(name, factory, meta);
                }
            });

            pendingPlugins.clear();

            evaluatePluginActivation(window.location.pathname);
        }
        function integratePendingO(){

            if(!started){
                console.warn('Runtime not started yet.');
                return;
            }

            // SERVICES
            pendingServices.splice(0).forEach(s => {

                if(services.has(s.name)){
                    console.warn(`Service "${s.name}" already exists.`);
                    return;
                }

                validateRequires(s.meta?.requires, services);

                const instance = s.factory(createScope());
                services.set(s.name, instance);
            });

            // PLUGINS
            pendingPlugins.splice(0).forEach(p => {

                if(instances.has(p.name)){
                    console.warn(`Plugin "${p.name}" already exists.`);
                    return;
                }

                validateRequires(p.meta?.requires, services, instances);

                const instance = p.factory(createScope());
                instances.set(p.name, instance);

                if(instance?.init){
                    instance.init();
                }
            });
        }

        function evaluatePluginActivation(route){

            const perms = services.get('permissions');
            const face  = services.get('face');

            plugins.forEach((plugin, name) => {

                const meta = pluginMeta.get(name);
                if(!meta) return;

                let shouldActivate = true;

                if(meta.activateOn){
                    shouldActivate = meta.activateOn(route);
                }

                if(shouldActivate && meta.permission){
                    const {group, sub} = meta.permission;
                    shouldActivate = perms?.can(group, sub) === true;
                }

                if(shouldActivate && meta.face){
                    shouldActivate = face.current() === meta.face;
                }

                if(shouldActivate && !plugin.__active){
                    plugin.mount?.();
                    plugin.__active = true;
                }

                if(!shouldActivate && plugin.__active){
                    plugin.unmount?.();
                    plugin.__active = false;
                }

            });
        }
        function evaluatePluginActivationO(route){

            const perms = services.get('permissions');
            const face  = services.get('face');

            instances.forEach((plugin, name) => {

                const meta = pluginMeta.get(name);
                if(!meta) return;

                let shouldActivate = true;

                // Route condition
                if(meta.activateOn){
                    shouldActivate = meta.activateOn(route);
                }

                // Permission condition
                if(shouldActivate && meta.permission){
                    const {group, sub} = meta.permission;
                    shouldActivate = perms?.can(group, sub) === true;
                }

                // Face condition (optional future)
                if(shouldActivate && meta.face){
                    shouldActivate = face.current() === meta.face;
                }

                if(shouldActivate){
                    plugin.mount?.();
                } else {
                    plugin.unmount?.();
                }

            });
        }

        function validateRequires(requires = [], servicesMap, pluginMap){

            requires.forEach(dep => {

                if(!servicesMap.has(dep) && !pluginMap?.has(dep)){
                    throw new Error(`Missing dependency: ${dep}`);
                }

            });
        }

        function lock(){
            registrationOpen = false;
        }

        function applyDomGuards(){

            const perms = services.get('permissions');

            document.querySelectorAll('[data-perm]')
                .forEach(el=>{
                    const [group, sub] = el.dataset.perm.split(':');
                    if(!perms.can(group,sub)){
                        el.remove();
                    }
                });
        }

        /* =========================
           SANITY
        ========================= */

        function sanity(){

            const issues = [];

            if(!services.has('state')) issues.push('Missing state');
            if(!services.has('navigation')) issues.push('Missing navigation');

            return {
                ok: issues.length === 0,
                issues
            };
        }

        /* =========================
           START
        ========================= */

        function start(){

            if(started){
                console.warn('[Runtime already started]');
                return;
            }

            started = true;

            emit('runtime:beforeStart');

            if(global.jQuery){
                services.set('jquery', global.jQuery);
            }

            pendingServices.forEach(({factory, meta}, name)=>{
                _registerService(name, factory, meta);
            });

            emit('runtime:servicesReady');

            const order = resolvePluginOrder();

            order.forEach(name=>{
                const { factory, meta } = pendingPlugins.get(name);
                _registerPlugin(name, factory, meta);
            });

            emit('runtime:started');

            if(config.dev){

                const report = sanity();

                if(!report.ok){
                    console.error('[Sanity failed]', report.issues);
                }
                else{
                    console.log('%c BoraRuntime started clean',
                        'color:#22c55e;font-weight:bold;');
                }

                console.table(
                    Array.from(timings.entries())
                        .map(([name, ms])=>({ plugin:name, mount_ms:ms.toFixed(2) }))
                );
            }

            const state = services.get('state');

            if(state){
                state.subscribe('route', (route)=>{
                    evaluatePluginActivation(route);
                });

                // evaluate once on boot
                evaluatePluginActivation(window.location.pathname);
            }

            Object.freeze(services);
            Object.freeze(plugins);
        }

        return Object.freeze({
            start,
            plugin:getPlugin,
            service:getService,
            integratePending,
            lock,
            on,
            emit,
            // handlePluginActivation,
            sanity,
            isStarted:()=>started,
            _registerPlugin,
            _registerService
        });
    }

    global.BoraRuntime = BoraRuntime;
    global.__BORA_REGISTER_PLUGIN__  = registerPluginDuringBuild;
    global.__BORA_REGISTER_SERVICE__ = registerServiceDuringBuild;

})(window);