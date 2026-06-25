__BORA_REGISTER_SERVICE__(
    'resources',
    function(scope){

        const loaders = {};

        function register(
            name,
            loader
        ){
            loaders[name] = loader;
        }

        async function get(
            name,
            options = {}
        ){
            const appState = await scope.getService('state');
            const state = appState.scope('resource');

            const cache = state.get(name);

            if (
                cache &&
                !options.force
            ) {
                return cache.data;
            }

            if (!loaders[name]) {
                throw new Error(
                    `Unknown resource: ${name}`
                );
            }

            const data =
                await loaders[name]();

            state.set(
                name,
                {
                    data,
                    loadedAt:
                        Date.now()
                }
            );

            return data;
        }

        function invalidate(
            name
        ){
            scope
                .getService('state')
                .scope('resource')
                .remove(name);

            scope.emit(
                `resource:${name}:invalidated`
            );
        }

        return {
            register,
            get,
            invalidate
        };
    }
);