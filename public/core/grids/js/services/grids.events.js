__BORA_REGISTER_SERVICE__(

    'grids.plugins',

    async function(){

        const plugins = {};

        function register(
            name,
            plugin
        ){

            plugins[name] = plugin;
        }

        async function mount(
            gridId,
            items = []
        ){

            for(const item of items){

                if(!plugins[item]){
                    continue;
                }

                await plugins[item]
                    .mount(gridId);
            }
        }

        return {
            register,
            mount
        };
    }
);