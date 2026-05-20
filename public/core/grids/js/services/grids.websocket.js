__BORA_REGISTER_SERVICE__(

    'grids.websocket',

    async function(scope){

        const store =

            await scope.getService(
                'grids.store'
            );

        let socket = null;

        /* =====================================================
         | Connect
         |===================================================== */

        function connect(

            gridId,

            url
        ){

            socket =
                new WebSocket(url);

            socket.onmessage =
                message => {

                    const event =
                        JSON.parse(
                            message.data
                        );

                    /*
                    |--------------------------------------------------------------------------
                    | Push into state
                    |--------------------------------------------------------------------------
                    */

                    store.set(

                        gridId,

                        'realtime',

                        event
                    );
                };
        }

        return {

            connect
        };
    }
);