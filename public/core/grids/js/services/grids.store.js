__BORA_REGISTER_SERVICE__(

    'grids.store',

    async function(scope){

        /*
        |--------------------------------------------------------------------------
        | Stores
        |--------------------------------------------------------------------------
        */

        const stores = {};

        /*
        |--------------------------------------------------------------------------
        | Listeners
        |--------------------------------------------------------------------------
        */

        const listeners = {};

        /* =====================================================
         | Ensure
         |===================================================== */

        function ensure(gridId){

            if(!stores[gridId]){

                stores[gridId] = {};
            }

            if(!listeners[gridId]){

                listeners[gridId] = [];
            }
        }

        /* =====================================================
         | Set
         |===================================================== */

        function set(

            gridId,

            key,

            value
        ){

            ensure(gridId);

            const old =
                stores[gridId][key];

            stores[gridId][key] =
                value;

            emit(

                gridId,

                {

                    type : 'state.changed',

                    key,

                    old,

                    value,

                    state :

                        stores[gridId]
                }
            );
        }

        /* =====================================================
         | Get
         |===================================================== */

        function get(

            gridId,

            key,

            fallback = null
        ){

            ensure(gridId);

            return (
                stores[gridId][key]
                ?? fallback
            );
        }

        /* =====================================================
         | Replace
         |===================================================== */

        function replace(

            gridId,

            state = {}
        ){

            ensure(gridId);

            stores[gridId] =
                state;

            emit(

                gridId,

                {

                    type : 'state.replaced',

                    state
                }
            );
        }

        /* =====================================================
         | Subscribe
         |===================================================== */

        function subscribe(

            gridId,

            callback
        ){

            ensure(gridId);

            listeners[gridId]
                .push(callback);
        }

        /* =====================================================
         | Emit
         |===================================================== */

        function emit(

            gridId,

            event
        ){

            (
                listeners[gridId]
                || []
            )

            .forEach(

                callback => {

                    callback(event);
                }
            );
        }

        return {

            set,
            get,
            replace,
            subscribe
        };
    }
);