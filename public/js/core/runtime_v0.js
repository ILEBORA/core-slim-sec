(function(global){

    /* ==================================================
       BUILD-TIME REGISTRIES
    ================================================== */

    const pendingPlugins  = new Map();
    const pendingServices = new Map();

    function registerPluginDuringBuild(name, factory){

        if(pendingPlugins.has(name)){
            console.warn('[BoraRuntime] Duplicate plugin registration:', name);
            return;
        }

        pendingPlugins.set(name, factory);

        // Late registration support
        if(global.__BORA_APP__?.isStarted()){
            global.__BORA_APP__._registerPlugin(name, factory);
        }
    }

    function registerServiceDuringBuild(name, factory){

        if(pendingServices.has(name)){
            console.warn('[BoraRuntime] Duplicate service registration:', name);
            return;
        }

        pendingServices.set(name, factory);

        // Late registration support
        if(global.__BORA_APP__?.isStarted()){
            global.__BORA_APP__._registerService(name, factory);
        }
    }

    /* ==================================================
       RUNTIME
    ================================================== */

    function BoraRuntime(config = {}){

        const services  = new Map();
        const plugins   = new Map();
        const events    = new Map();
        const timings   = new Map();

        let started = false;

        /* =========================
           INTERNAL EVENT BUS
        ========================= */

        function on(event, handler){
            if(!events.has(event)){
                events.set(event, []);
            }
            events.get(event).push(handler);
        }

        function emit(event, payload){
            if(!events.has(event)) return;

            events.get(event).forEach(fn=>{
                try{ fn(payload); }
                catch(err){
                    console.error('[BoraRuntime event error]', err);
                }
            });
        }

        /* =========================
           SERVICE REGISTRATION
        ========================= */

        function _registerService(name, factory){

            if(services.has(name)){
                console.warn('[BoraRuntime] Service already exists:', name);
                return;
            }

            try{
                const instance = factory(createScope());
                services.set(name, instance);
            }
            catch(err){
                console.error('[BoraRuntime] Service failed:', name, err);
            }
        }

        /* =========================
           PLUGIN REGISTRATION
        ========================= */

        function _registerPlugin(name, factory){

            if(plugins.has(name)){
                console.warn('[BoraRuntime] Plugin already mounted:', name);
                return;
            }

            try{

                const startTime = performance.now();

                const instance = factory(createScope());
                plugins.set(name, instance);

                if(instance?.mount){
                    instance.mount();
                }
                else if(instance?.init){
                    // Backward compatibility
                    instance.init();
                }

                if(config.dev){
                    const duration = performance.now() - startTime;
                    timings.set(name, duration);
                }

            }
            catch(err){
                console.error('[BoraRuntime] Plugin crashed:', name, err);
            }
        }

        /* =========================
           SCOPE FACTORY
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

        /* =========================
           ACCESSORS
        ========================= */

        function getService(name){
            return services.get(name);
        }

        function hasService(name){
            return services.has(name);
        }

        function getPlugin(name){
            return plugins.get(name);
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

        /* =========================
           START SEQUENCE
        ========================= */

        function start(){

            if(started){
                console.warn('[BoraRuntime] Already started.');
                return;
            }

            started = true;

            emit('runtime:beforeStart');

            // Auto inject jQuery
            if(global.jQuery){
                services.set('jquery', global.jQuery);
            }

            // Register services
            pendingServices.forEach((factory, name)=>{
                _registerService(name, factory);
            });

            emit('runtime:servicesReady');

            // Register plugins
            pendingPlugins.forEach((factory, name)=>{
                _registerPlugin(name, factory);
            });

            emit('runtime:started');

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
                    Array.from(timings.entries())
                        .map(([name, ms])=>({ plugin:name, mount_ms:ms.toFixed(2) }))
                );
            }
        }

        /* =========================
           PUBLIC API
        ========================= */

        return Object.freeze({
            start,
            plugin: getPlugin,
            service: getService,
            on,
            emit,
            isStarted: ()=>started,
            sanity,

            // Internal (used for late module load)
            _registerPlugin,
            _registerService
        });
    }

    /* ==================================================
       GLOBAL SURFACE
    ================================================== */

    global.BoraRuntime = BoraRuntime;
    global.__BORA_REGISTER_PLUGIN__  = registerPluginDuringBuild;
    global.__BORA_REGISTER_SERVICE__ = registerServiceDuringBuild;

})(window);