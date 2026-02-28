__BORA_REGISTER_SERVICE__('devtools', function(scope){

    const runtime = globalThis.__BORA_APP__;

    function inspect(){

        return {
            services: runtime ? Object.keys(runtime._services?.() || {}) : [],
            plugins: runtime ? Object.keys(runtime._plugins?.() || {}) : [],
            state: scope.getService('state')?.getAll?.() || {}
        };
    }

    function snapshot(label){

        const stateService = scope.getService('state');

        return {
            label,
            time: new Date(),
            state: stateService?.getAll?.()
        };
    }

    return { inspect, snapshot };
});