__BORA_REGISTER_SERVICE__('grids.plugins', async function(scope){

    const registry =
        await scope.getService(
            'grids.registry'
        );

    const renderers =
        await scope.getService(
            'grids.renderers'
        );

    /* =====================================================
     | Helpers
     |===================================================== */

    function ensureStore(grid){

        grid.__plugins ||= new Map();

        return grid.__plugins;
    }

    function normalize(
        name,
        plugin,
        options = {}
    ){

        return {

            name,

            options,

            mounted: false,

            instance: plugin
        };
    }

    /* =====================================================
     | Mount
     |===================================================== */

    async function mount(
        grid,
        name,
        options = {}
    ){

        const store =
            ensureStore(grid);

        /*
        |--------------------------------------------------------------------------
        | Already mounted
        |--------------------------------------------------------------------------
        */

        if(store.has(name)){

            return store.get(name);
        }

        /*
        |--------------------------------------------------------------------------
        | Load plugin
        |--------------------------------------------------------------------------
        */

        const plugin =
            await scope.getPlugin(name);

        if(!plugin){

            throw new Error(

                `[grids.plugins] Plugin "${name}" not found`
            );
        }

        /*
        |--------------------------------------------------------------------------
        | Compatibility
        |--------------------------------------------------------------------------
        */

        if(
            plugin.compatible &&
            Array.isArray(plugin.compatible)
        ){

            const renderer =
                grid.state.renderer;

            if(
                !plugin.compatible.includes(
                    renderer
                )
            ){

                return null;
            }
        }

        /*
        |--------------------------------------------------------------------------
        | Wrapper
        |--------------------------------------------------------------------------
        */

        const wrapped =
            normalize(
                name,
                plugin,
                options
            );

        /*
        |--------------------------------------------------------------------------
        | Mount lifecycle
        |--------------------------------------------------------------------------
        */

        if(plugin.mount){

            await plugin.mount(

                grid,

                options
            );
        }

        wrapped.mounted = true;

        store.set(
            name,
            wrapped
        );

        /*
        |--------------------------------------------------------------------------
        | Events
        |--------------------------------------------------------------------------
        */

        grid.emit(

            'plugin.mounted',

            {

                plugin: name,

                options
            }
        );

        return wrapped;
    }

    /* =====================================================
     | Unmount
     |===================================================== */

    async function unmount(
        grid,
        name
    ){

        const store =
            ensureStore(grid);

        const wrapped =
            store.get(name);

        if(!wrapped){

            return;
        }

        const plugin =
            wrapped.instance;

        /*
        |--------------------------------------------------------------------------
        | Unmount lifecycle
        |--------------------------------------------------------------------------
        */

        if(plugin.unmount){

            await plugin.unmount(grid);
        }

        store.delete(name);

        /*
        |--------------------------------------------------------------------------
        | Events
        |--------------------------------------------------------------------------
        */

        grid.emit(

            'plugin.unmounted',

            {

                plugin: name
            }
        );
    }

    /* =====================================================
     | Introspection
     |===================================================== */

    function mounted(
        grid,
        name
    ){

        return ensureStore(grid)
            .has(name);
    }

    function all(grid){

        return Array.from(

            ensureStore(grid).values()
        );
    }

    /* =====================================================
     | Auto Plugins
     |===================================================== */

    async function autoload(grid){

        const renderer =
            renderers.current(grid);

        if(!renderer){

            return;
        }

        /*
        |--------------------------------------------------------------------------
        | Renderer plugin
        |--------------------------------------------------------------------------
        */

        if(renderer.plugin){

            await mount(

                grid,

                renderer.plugin
            );
        }

        /*
        |--------------------------------------------------------------------------
        | Global defaults
        |--------------------------------------------------------------------------
        */

        const defaults = [

            'grids.pagination',

            'grids.search',

            'grids.contextmenu'
        ];

        for(const name of defaults){

            try {

                await mount(
                    grid,
                    name
                );

            } catch(err){

                console.warn(

                    `[grids.plugins] Failed to autoload "${name}"`,

                    err
                );
            }
        }
    }

    /* =====================================================
     | Config
     |===================================================== */

    function configure(
        grid,
        name,
        options = {}
    ){

        const store =
            ensureStore(grid);

        const plugin =
            store.get(name);

        if(!plugin){

            return null;
        }

        plugin.options = {

            ...plugin.options,

            ...options
        };

        grid.emit(

            'plugin.configured',

            {

                plugin: name,

                options
            }
        );

        return plugin;
    }

    return {

        mount,

        unmount,

        mounted,

        all,

        autoload,

        configure
    };

});