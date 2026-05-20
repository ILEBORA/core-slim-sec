__BORA_REGISTER_SERVICE__('grids.renderers', async function(scope){

    const registry =
        await scope.getService(
            'grids.registry'
        );

    const transport =
        await scope.getService(
            'grids.transport'
        );

    const state =
        await scope.getService(
            'grids.state'
        );

    /* =====================================================
     | Registration
     |===================================================== */

    function register(
        name,
        definition = {}
    ){

        return registry.registerRenderer(

            name,

            {

                name,

                label:
                    definition.label
                    || name,

                icon:
                    definition.icon
                    || 'grid',

                plugin:
                    definition.plugin
                    || null,

                responsive:
                    definition.responsive
                    ?? true,

                capabilities:
                    definition.capabilities
                    || {},

                ...definition
            }
        );
    }

    function get(name){

        return registry.getRenderer(name);
    }

    function available(){

        return registry.allRenderers();
    }

    function exists(name){

        return !!get(name);
    }

    /* =====================================================
     | Runtime
     |===================================================== */

    function current(grid){

        return get(
            grid.state.renderer
        );
    }

    async function activate(
        grid,
        rendererName
    ){

        const renderer =
            get(rendererName);

        if(!renderer){

            throw new Error(

                `[grids.renderers] Renderer "${rendererName}" not registered`
            );
        }

        /*
        |--------------------------------------------------------------------------
        | State
        |--------------------------------------------------------------------------
        */

        state.setRenderer(

            grid,

            rendererName
        );

        /*
        |--------------------------------------------------------------------------
        | Plugin
        |--------------------------------------------------------------------------
        */

        if(renderer.plugin){

            await grid.use(
                renderer.plugin
            );
        }

        /*
        |--------------------------------------------------------------------------
        | Events
        |--------------------------------------------------------------------------
        */

        grid.emit(

            'renderer.activated',

            {

                renderer
            }
        );

        return renderer;
    }

    async function deactivate(grid){

        const renderer =
            current(grid);

        if(!renderer){

            return;
        }

        grid.emit(

            'renderer.deactivated',

            {

                renderer
            }
        );
    }

    async function switchRenderer(
        grid,
        rendererName,
        reload = true
    ){

        const previous =
            current(grid);

        await deactivate(grid);

        const renderer =
            await activate(

                grid,

                rendererName
            );

        /*
        |--------------------------------------------------------------------------
        | Reload server-rendered HTML
        |--------------------------------------------------------------------------
        */

        if(reload){

            await transport.render(

                grid,

                rendererName
            );
        }

        grid.emit(

            'renderer.changed',

            {

                previous,

                current: renderer
            }
        );

        return renderer;
    }

    /* =====================================================
     | Capabilities
     |===================================================== */

    function supports(
        rendererName,
        capability
    ){

        const renderer =
            get(rendererName);

        if(!renderer){

            return false;
        }

        return !!renderer
            ?.capabilities
            ?.[capability];
    }

    return {

        register,

        get,

        exists,

        available,

        current,

        activate,

        deactivate,

        switch: switchRenderer,

        supports
    };

});