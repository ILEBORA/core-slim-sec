__BORA_REGISTER_SERVICE__(

    'grids.sse',

    async function(scope){

        const subscriptions =

            await scope.getService(
                'grids.subscriptions'
            );

        const sources = {};

        /* =====================================================
         | Connect
         |===================================================== */

        function connect(

            gridId,

            url
        ){

            if(sources[gridId]){

                return sources[gridId];
            }

            const source =
                new EventSource(url);

            /*
            |--------------------------------------------------------------------------
            | Generic messages
            |--------------------------------------------------------------------------
            */

            source.onmessage = event => {

                const payload =
                    JSON.parse(
                        event.data
                    );

                subscriptions.publish(

                    gridId,

                    'sse.message',

                    payload
                );
            };

            /*
            |--------------------------------------------------------------------------
            | Patch stream
            |--------------------------------------------------------------------------
            */

            source.addEventListener(

                'patch',

                event => {

                    subscriptions.publish(

                        gridId,

                        'sse.patch',

                        JSON.parse(
                            event.data
                        )
                    );
                }
            );

            /*
            |--------------------------------------------------------------------------
            | State updates
            |--------------------------------------------------------------------------
            */

            source.addEventListener(

                'state',

                event => {

                    subscriptions.publish(

                        gridId,

                        'sse.state',

                        JSON.parse(
                            event.data
                        )
                    );
                }
            );

            /*
            |--------------------------------------------------------------------------
            | Errors
            |--------------------------------------------------------------------------
            */

            source.onerror = error => {

                subscriptions.publish(

                    gridId,

                    'sse.error',

                    error
                );
            };

            sources[gridId] =
                source;

            return source;
        }

        /* =====================================================
         | Disconnect
         |===================================================== */

        function disconnect(gridId){

            if(!sources[gridId]){
                return;
            }

            sources[gridId].close();

            delete sources[gridId];
        }

        return {

            connect,
            disconnect
        };
    }
);