__BORA_REGISTER_SERVICE__(

    'grids.optimistic',

    async function(scope){

        const store =

            await scope.getService(
                'grids.store'
            );

        /* =====================================================
         | Apply
         |===================================================== */

        function apply(

            gridId,

            mutation
        ){

            mutation(store);
        }

        return {

            apply
        };
    }
);