__BORA_REGISTER_SERVICE__(
    'resources',

    async function(scope){

        const loaders = {};
        const projectors = {};

        const appState = await scope.getService('state');
        const state = appState.bucket('resource');
        
        function project(type, projector){

            projectors[type] ??= [];
        
            projectors[type].push(
                projector
            );
        
        }

        function applyProjectors(
            type,
            data
        ){
        
            const list =
                projectors[type];
        
            if(!list){
                return;
            }
        
            list.forEach(projector => {
        
                projector(data);
        
            });
        
        }

        function merge(
            type,
            id,
            patch,
            meta = {}
        ){
        
            const k = key(type, id);
        
            const current = state.get(k);
        
            if(!current){
        
                console.warn(
                    `${type}.${id} wasn't loaded.`
                );
        
                return null;
            }
        
            const data = structuredClone(
                current.data
            );
        
            deepMerge(
                data,
                patch
            );
        
            const payload = makePayload(
                data,
                {
                    ...current.meta,
                    ...meta
                },
                {
                    type: 'merge'
                }
            );
        
            state.set(
                k,
                payload
            );
        
            return data;
        }
        
        function deepMerge(target, source){
        
            if(!source){
                return target;
            }
        
            Object.entries(source).forEach(([key, value]) => {
        
                if(
                    value &&
                    typeof value === 'object' &&
                    !Array.isArray(value)
                ){
        
                    target[key] ??= {};
        
                    deepMerge(
                        target[key],
                        value
                    );
        
                }else{
        
                    target[key] = value;
        
                }
        
            });
        
            return target;
        }

        function key(type, id = null){

            if (id == null) {
                return type;
            }
        
            if (typeof id === 'object') {
        
                return `${type}:${JSON.stringify(id)}`;
        
            }
        
            return `${type}:${id}`;
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

                applyProjectors(
                    type,
                    data
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

            applyProjectors(
                type,
                data
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

            console.log(
                '[PATCH]',
                k,
                current
            );

            if (!current) {
                console.warn(
                    `${type} wasn't loaded. Refreshing.`
                );
            
                return refresh(type, id);
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

            const operation =
                result.operation ?? {

                    action: 'refreshed',

                    items: data

                };

            applyProjectors(
        
                type,
        
                operation
        
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
            merge,

            watch,

            peek,
            has,

            invalidate,
            remove,

            project
        };
    }
);