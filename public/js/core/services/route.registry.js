__BORA_REGISTER_SERVICE__('route.registry', function(){
    const baseRoutes = rd('routes')||{};

    const dynamicRoutes = {};                     // JS overrides
    const waiters       = {};

    function register(name, resolver){

        dynamicRoutes[name] = resolver;

        // 🔥 resolve any waiters
        if (waiters[name]){
            waiters[name].forEach(fn => fn(resolver));
            delete waiters[name];
        }
    }

    function resolve(name, params = {}){
        // console.log('[resolve] name:', name);
        // console.log('[resolve] available:', Object.keys(baseRoutes));
        // 1. JS override
        if (dynamicRoutes[name]){
            return dynamicRoutes[name](params);
        }

        // 2. PHP route
        const config = baseRoutes[name];

        if (config){
            return buildFromConfig(config, params);
        }

        // 3. fallback error
        throw new Error(`[routeRegistry] Unknown route: ${name}`);
    }

    async function resolveAsync(name, params = {}, timeout = 5000){

        try {
            return resolve(name, params);
        } catch (err){

            // 🔥 wait only if missing
            const resolver = await waitFor(name, timeout);

            return resolver(params);
        }
    }

    function waitFor(name, timeout = 5000){

        // already available?
        if (dynamicRoutes[name]){
            return Promise.resolve(dynamicRoutes[name]);
        }

        return new Promise((resolve, reject) => {

            if (!waiters[name]){
                waiters[name] = [];
            }

            waiters[name].push(resolve);

            setTimeout(() => {
                reject(new Error(`[routeRegistry] Timeout waiting for route: ${name}`));
            }, timeout);
        });
    }

    function buildFromConfig(config, params){

        const result = { ...config };

        if (Array.isArray(config.tabs)){
            result.tabs = config.tabs.map(tab => ({
                ...tab,
                url: interpolate(tab.url, params)
            }));
        }

        result.activeTab = params.tab || config.defaultTab;

        return result;
    }

    function interpolate(url, params){
        return url.replace(/\{(\w+)\}/g, (_, key) => params[key] ?? '');
    }

    function has(name){
        return !!dynamicRoutes[name] || !!baseRoutes[name];
    }

    function all(){
        return {
            ...baseRoutes,
            ...dynamicRoutes
        };
    }

    return {
        register,
        resolve,
        resolveAsync, // 🔥 important addition
        waitFor,
        has,
        all
    };
});