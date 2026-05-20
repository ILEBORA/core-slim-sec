__BORA_REGISTER_SERVICE__(

    'grids.stream',

    async function(scope){

        const sse =

            await scope.getService(
                'grids.sse'
            );

        const store =

            await scope.getService(
                'grids.store'
            );

        const patches =

            await scope.getService(
                'grids.patchResolver'
            );

        const subscriptions =

            await scope.getService(
                'grids.subscriptions'
            );

        /* =====================================================
         | Boot
         |===================================================== */

        async function boot(

            gridId,

            url
        ){

            /*
            |--------------------------------------------------------------------------
            | Connect SSE
            |--------------------------------------------------------------------------
            */

            sse.connect(
                gridId,
                url
            );

            /*
            |--------------------------------------------------------------------------
            | Patch updates
            |--------------------------------------------------------------------------
            */

            subscriptions.subscribe(

                gridId,

                'sse.patch',

                payload => {

                    patches.apply(
                        payload.patches || []
                    );
                }
            );

            /*
            |--------------------------------------------------------------------------
            | State updates
            |--------------------------------------------------------------------------
            */

            subscriptions.subscribe(

                gridId,

                'sse.state',

                payload => {

                    Object.entries(
                        payload.state || {}
                    )

                    .forEach(

                        ([key, value]) => {

                            store.set(

                                gridId,

                                key,

                                value
                            );
                        }
                    );
                }
            );
        }

        return {

            boot
        };
    }
);