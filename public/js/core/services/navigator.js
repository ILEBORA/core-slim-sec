__BORA_REGISTER_SERVICE__('navigator', async function(scope){

    const routeRegistry = await scope.getService('route.registry');
    const navigation    = await scope.getService('navigation');
    const popup         = await scope.getPlugin('popup');

    async function go({ route, params = {}, surface = 'page', ...rest }){
        
        let config;
        try {
            config = routeRegistry.resolve(route, params);
        } catch (err) {
            const fn = await routeRegistry.waitFor(route);
            config = fn(params);
        }
            

        if (surface === 'popup'){

            updateUrl(route, params, surface);

            return popup.openPopupSmart({
                key: route,
                id: params.id,
                tab: params.tab,
                factory: () => ({
                    ...config,
                    ...rest
                })
            });
        }

        if (surface === 'page'){
            updateUrl(route, params, surface);
            return navigation.go(config.url);
        }
    }

    function updateUrl(route, params, surface){

        const url = new URL(window.location);

        url.searchParams.set('route', route);
        url.searchParams.set('surface', surface);

        Object.entries(params).forEach(([k,v]) => {
            if (v != null) url.searchParams.set(k, v);
        });

        history.pushState({}, '', url);
    }

    return { go };
});