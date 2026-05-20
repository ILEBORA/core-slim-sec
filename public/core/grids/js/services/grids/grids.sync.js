__BORA_REGISTER_SERVICE__(

    'grids.sync',

    async function(scope){

        const store =

            await scope.getService(
                'grids.store'
            );

        /*
        |--------------------------------------------------------------------------
        | Cross-tab sync
        |--------------------------------------------------------------------------
        */

        window.addEventListener(

            'storage',

            event => {

                if(
                    !event.key.startsWith(
                        'grid:'
                    )
                ){

                    return;
                }

                const gridId =
                    event.key.replace(
                        'grid:',
                        ''
                    );

                store.replace(

                    gridId,

                    JSON.parse(
                        event.newValue
                    )
                );
            }
        );

        return {};
    }
);