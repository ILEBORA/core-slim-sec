__BORA_REGISTER_SERVICE__('grids.registry', async function(scope){

    /* =====================================================
     | Internal Stores
     |===================================================== */

    const registries = {

        renderers: new Map(),

        plugins: new Map(),

        toolbars: new Map(),

        columns: new Map(),

        actions: new Map(),

        views: new Map()
    };

    /* =====================================================
     | Helpers
     |===================================================== */

    function ensure(type){

        if(!registries[type]){

            throw new Error(

                `[grids.registry] Unknown registry: ${type}`
            );
        }

        return registries[type];
    }

    function register(
        type,
        name,
        definition
    ){

        const registry =
            ensure(type);

        registry.set(
            name,
            definition
        );

        return definition;
    }

    function get(
        type,
        name
    ){

        return ensure(type)
            .get(name);
    }

    function has(
        type,
        name
    ){

        return ensure(type)
            .has(name);
    }

    function remove(
        type,
        name
    ){

        return ensure(type)
            .delete(name);
    }

    function all(type){

        return Array.from(

            ensure(type).entries()

        ).map(([name, definition]) => ({

            name,

            definition
        }));
    }

    /* =====================================================
     | Renderers
     |===================================================== */

    function registerRenderer(
        name,
        definition
    ){

        return register(
            'renderers',
            name,
            definition
        );
    }

    function getRenderer(name){

        return get(
            'renderers',
            name
        );
    }

    function allRenderers(){

        return all('renderers');
    }

    /* =====================================================
     | Plugins
     |===================================================== */

    function registerPlugin(
        name,
        definition
    ){

        return register(
            'plugins',
            name,
            definition
        );
    }

    function getPlugin(name){

        return get(
            'plugins',
            name
        );
    }

    function allPlugins(){

        return all('plugins');
    }

    /* =====================================================
     | Toolbars
     |===================================================== */

    function registerToolbar(
        name,
        definition
    ){

        return register(
            'toolbars',
            name,
            definition
        );
    }

    function getToolbar(name){

        return get(
            'toolbars',
            name
        );
    }

    function allToolbars(){

        return all('toolbars');
    }

    /* =====================================================
     | Columns
     |===================================================== */

    function registerColumn(
        name,
        definition
    ){

        return register(
            'columns',
            name,
            definition
        );
    }

    function getColumn(name){

        return get(
            'columns',
            name
        );
    }

    function allColumns(){

        return all('columns');
    }

    /* =====================================================
     | Actions
     |===================================================== */

    function registerAction(
        name,
        definition
    ){

        return register(
            'actions',
            name,
            definition
        );
    }

    function getAction(name){

        return get(
            'actions',
            name
        );
    }

    function allActions(){

        return all('actions');
    }

    /* =====================================================
     | Views
     |===================================================== */

    function registerView(
        name,
        definition
    ){

        return register(
            'views',
            name,
            definition
        );
    }

    function getView(name){

        return get(
            'views',
            name
        );
    }

    function allViews(){

        return all('views');
    }

    /* =====================================================
     | Export
     |===================================================== */

    return {

        register,

        get,

        has,

        remove,

        all,

        registerRenderer,

        getRenderer,

        allRenderers,

        registerPlugin,

        getPlugin,

        allPlugins,

        registerToolbar,

        getToolbar,

        allToolbars,

        registerColumn,

        getColumn,

        allColumns,

        registerAction,

        getAction,

        allActions,

        registerView,

        getView,

        allViews
    };

});