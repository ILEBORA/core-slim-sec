__BORA_REGISTER_SERVICE__(

    'grids.offline',

    async function(scope){

        const queue = [];

        /* =====================================================
         | Is offline
         |===================================================== */

        function offline(){

            return !navigator.onLine;
        }

        /* =====================================================
         | Queue mutation
         |===================================================== */

        function push(payload){

            queue.push(payload);
        }

        /* =====================================================
         | Replay
         |===================================================== */

        async function replay(

            callback
        ){

            while(queue.length){

                const item =
                    queue.shift();

                await callback(item);
            }
        }

        /* =====================================================
         | Listen reconnect
         |===================================================== */

        window.addEventListener(

            'online',

            () => {

                console.log(
                    '[Grids] Reconnected'
                );
            }
        );

        return {

            offline,
            push,
            replay
        };
    }
);