__BORA_REGISTER_SERVICE__(
    'resources',
    async function(scope){

        const loaders = {};
        const watchers = {};

        const appState = await scope.getService('state');
        const state = appState.scope('resource');

        function key(
            type,
            id = null
        ){
            return id == null
                ? type
                : `${type}:${id}`;
        }

        function register(
            type,
            loader
        ){
            loaders[type] = loader;
        }

        async function get(
            type,
            id = null
        ){

            const k =
                key(type, id);

            const cache =
                state.get(k);

            if (cache) {
                return cache.data;
            }

            if (!loaders[type]) {
                throw new Error(
                    `Resource loader not registered: ${type}`
                );
            }

            const data =
                await loaders[type](id);

            state.set(
                k,
                {
                    data,
                    loadedAt:
                        Date.now()
                }
            );

            return data;
        }

        async function refreshO(
            type,
            id = null
        ){

            if (!loaders[type]) {
                return null;
            }

            const k =
                key(type, id);

            const data =
                await loaders[type](id);

            state.set(
                k,
                {
                    data,
                    loadedAt:
                        Date.now()
                }
            );

            return data;
        }

        async function refresh(type, id){

            const k =
                key(type, id);

            scope.emit(
                `${type}.refreshing`,
                {
                    type,
                    id
                }
            );

            const data =
                await loaders[type](id);

            state.set(
                k,
                {
                    data,
                    loadedAt:
                        Date.now()
                }
            );

            scope.emit(
                `${type}.refreshed`,
                {
                    type,
                    id,
                    data
                }
            );

            return data;
        }

        function invalidate(
            type,
            id = null
        ){

            const k =
                key(type, id);

            state.remove(k);

            scope.emit(
                `resource.invalidated`,
                {
                    type,
                    id
                }
            );
        }

        function remove(
            type,
            id = null
        ){
            invalidate(
                type,
                id
            );
        }

        function patch(
            type,
            id,
            updater
        ){

            const k =
                key(type, id);

            const current =
                state.get(k);

            if (!current) {
                return;
            }

            const next =
                updater(
                    structuredClone(
                        current.data
                    )
                );

            state.set(
                k,
                {
                    ...current,
                    data: next
                }
            );
        }

        async function watch(
            type,
            id,
            callback
        ){
            console.log(
                '[WATCH]',
                type,
                id
            );

            const k =
                key(type, id);

            const fn =
                payload => {

                    callback(
                        payload.data
                    );
                };

            state.subscribe(
                k,
                fn
            );

            const current =
                state.get(k);

            if (current) {
                callback(
                    current.data
                );
            } else {

                callback(
                    await get(
                        type,
                        id
                    )
                );
            }

            return () =>
                state.unsubscribe(
                    k,
                    fn
                );
        }

        return {
            register,
            get,
            watch,
            patch,
            refresh,
            invalidate,
            remove
        };
    }
);