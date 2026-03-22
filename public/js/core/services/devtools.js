__BORA_REGISTER_SERVICE__('devtools', async function(scope){

    const runtime = globalThis.__BORA_APP__;

    async function inspect(){

        const services = await runtime?._getServices?.() || new Map();
        const plugins  = await runtime?._getPlugins?.() || new Map();
        const meta     = await runtime?._getMeta?.() || new Map();

        return {
            services: Array.from(services.keys()),
            plugins: Array.from(plugins.keys()),
            meta: Object.fromEntries(meta),
            state: scope.getService('state')?.getAll?.() || {}
        };
    }

    async function snapshot(label = 'snapshot'){

        const stateService = await scope.getService('state');

        return {
            label,
            time: new Date().toISOString(),
            state: stateService?.getAll?.() || {}
        };
    }

    return { inspect, snapshot };
});