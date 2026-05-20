__BORA_REGISTER_SERVICE__(

    'grids.runtime',

    async function(scope){

        const store =

            await scope.getService(
                'grids.store'
            );

        const patchResolver =

            await scope.getService(
                'grids.patchResolver'
            );

        /* =====================================================
         | Boot
         |===================================================== */

        function boot(
            gridId
        ){

            /*
            |--------------------------------------------------------------------------
            | Subscribe to state
            |--------------------------------------------------------------------------
            */

            store.subscribe(

                gridId,

                async event => {

                    await handleEvent(
                        gridId,
                        event
                    );
                }
            );
        }

        /* =====================================================
         | Handle
         |===================================================== */

        async function handleEvent(

            gridId,

            event
        ){

            /*
            |--------------------------------------------------------------------------
            | Fetch patches
            |--------------------------------------------------------------------------
            */

            const response =
                await fetch(

                    `/api/modules/grids/patches/${gridId}`,

                    {

                        method : 'POST',

                        headers : {

                            'Content-Type':
                                'application/json'
                        },

                        body : JSON.stringify(
                            event
                        )
                    }
                );

            const json =
                await response.json();

            /*
            |--------------------------------------------------------------------------
            | Apply patches
            |--------------------------------------------------------------------------
            */

            patchResolver.apply(
                json.patches || []
            );
        }

        return {

            boot
        };
    }
);