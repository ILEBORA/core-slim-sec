__BORA_REGISTER_SERVICE__(

    'grids.subscriptions',

    async function(scope){

        const subscriptions = {};

        /* =====================================================
         | Ensure
         |===================================================== */

        function ensure(gridId){

            if(!subscriptions[gridId]){

                subscriptions[gridId] = {};
            }
        }

        /* =====================================================
         | Subscribe
         |===================================================== */

        function subscribe(

            gridId,

            event,

            callback
        ){

            ensure(gridId);

            subscriptions[gridId][event] =

                subscriptions[gridId][event]
                || [];

            subscriptions[gridId][event]
                .push(callback);
        }

        /* =====================================================
         | Publish
         |===================================================== */

        function publish(

            gridId,

            event,

            payload = {}
        ){

            ensure(gridId);

            (

                subscriptions[gridId][event]
                || []

            )

            .forEach(

                callback => {

                    callback(payload);
                }
            );
        }

        /* =====================================================
         | Unsubscribe
         |===================================================== */

        function unsubscribe(

            gridId,

            event
        ){

            ensure(gridId);

            delete subscriptions[
                gridId
            ][event];
        }

        return {

            subscribe,
            publish,
            unsubscribe
        };
    }
);