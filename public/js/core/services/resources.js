__BORA_REGISTER_SERVICE__(
    'resources',

    async function(scope){

        const loaders = {};

        const appState =
            await scope.getService(
                'state'
            );

        const state =
            appState.bucket(
                'resource'
            );

        function key(
            type,
            id = null
        ){
            return id == null
                ? type
                : `${type}:${id}`;
        }

        function makePayload(
            data,
            meta = {},
            update = {
                type: 'full'
            }
        ){
            return {
                data,
                meta,
                update,
                loadedAt:
                    Date.now()
            };
        }

        function register(
            type,
            loader
        ){
            loaders[type] = loader;
        }

        function has(
            type,
            id = null
        ){
            return state.has(
                key(type, id)
            );
        }

        function peek(
            type,
            id = null
        ){
            return state.get(
                key(type, id)
            );
        }

        async function get(
            type,
            id = null,
            meta = {}
        ){
             scope.emit(`${type}.loading`, {
                type,
                id
            });

            try{

                const k =
                    key(type, id);

                const cache =
                    state.get(k);

                if (cache) {
                    return cache.data;
                }

                const loader =
                    loaders[type];

                if (!loader) {
                    throw new Error(
                        `Resource loader not registered: ${type}`
                    );
                }

                const data =
                    await loader(id);

                state.set(
                    k,
                    makePayload(
                        data,
                        {
                            source:
                                'initial',
                            ...meta
                        }
                    )
                );

                return data;
            }finally{

                scope.emit(`${type}.loaded`, {
                    type,
                    id
                });

            }
        }

        async function refresh(
            type,
            id = null,
            meta = {}
        ){

            const loader =
                loaders[type];

            if (!loader) {
                return null;
            }

            const k =
                key(type, id);

            scope.emit(
                `${type}.refreshing`,
                {
                    type,
                    id,
                    meta
                }
            );

            const data =
                await loader(id);

            const payload =
                makePayload(
                    data,
                    meta
                );

            state.set(
                k,
                payload
            );

            scope.emit(
                `${type}.refreshed`,
                {
                    type,
                    id,
                    data,
                    meta
                }
            );

            return data;
        }

        function invalidate(
            type,
            id = null
        ){

            state.remove(
                key(type, id)
            );

            scope.emit(
                'resource.invalidated',
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

        function set(
            type,
            id,
            data,
            meta = {},
            update = {
                type: 'full'
            }
        ){

            const k =
                key(type, id);

            const payload =
                makePayload(
                    data,
                    meta,
                    update
                );

            state.set(
                k,
                payload
            );

            return data;
        }

        function patch(
            type,
            id,
            updater,
            meta = {}
        ){

            const k =
                key(type, id);

            const current =
                state.get(k);

            if (!current) {
                return null;
            }

            const result =
                updater(
                    structuredClone(
                        current.data
                    )
                );

            let data;
            let update = {
                type: 'full'
            };

            if (
                result &&
                typeof result ===
                    'object' &&
                'data' in result
            ){
                data =
                    result.data;

                update =
                    result.update
                    ||
                    update;

                meta = {
                    ...current.meta,
                    ...meta,
                    ...(result.meta || {})
                };
            }
            else {

                data =
                    result;

                meta = {
                    ...current.meta,
                    ...meta
                };
            }

            const payload =
                makePayload(
                    data,
                    meta,
                    update
                );

            state.set(
                k,
                payload
            );

            return data;
        }

        async function watch(
            type,
            id,
            callback
        ){

            const k =
                key(type, id);

            console.log(
                '[WATCH]',
                k
            );

            const fn =
                payload => {

                    callback(
                        payload
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
                    current
                );

            }
            else {

                const data =
                    await get(
                        type,
                        id
                    );

                callback(
                    makePayload(
                        data,
                        {
                            source:
                                'initial'
                        }
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
            refresh,

            set,
            patch,

            watch,

            peek,
            has,

            invalidate,
            remove
        };
    }
);