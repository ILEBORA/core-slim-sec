__BORA_REGISTER_SERVICE__('route.registry', function(){

    const routes = {};
    const waiters = {};

    function register(name, resolver){

        routes[name] = resolver;

        if (waiters[name]){
            waiters[name].forEach(fn => fn(resolver));
            delete waiters[name];
        }
    }

    function resolve(name, params = {}){
        const route = routes[name];

        if (!route){
            throw new Error(`[routeRegistry] Unknown route: ${name}`);
        }

        return route(params);
    }

    function waitFor(name, timeout = 5000){

        if (routes[name]){
            return Promise.resolve(routes[name]);
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

    return {
        register,
        resolve,
        waitFor
    };
});