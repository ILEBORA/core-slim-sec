__BORA_REGISTER_SERVICE__('grids.actions', async function(scope){

    const registry =
        await scope.getService(
            'grids.registry'
        );

    const selection =
        await scope.getService(
            'grids.selection'
        );

    /* =====================================================
     | Registration
     |===================================================== */

    function register(
        name,
        definition = {}
    ){

        const action = {

            name,

            label:
                definition.label
                || name,

            icon:
                definition.icon
                || null,

            confirm:
                definition.confirm
                || false,

            bulk:
                definition.bulk
                || false,

            visible:
                definition.visible
                || (() => true),

            enabled:
                definition.enabled
                || (() => true),

            handler:
                definition.handler
                || null,

            ...definition
        };

        registry.registerAction(
            name,
            action
        );

        return action;
    }

    function get(name){

        return registry.getAction(name);
    }

    function exists(name){

        return !!get(name);
    }

    function all(){

        return registry.allActions();
    }

    function remove(name){

        return registry.remove(
            'actions',
            name
        );
    }

    /* =====================================================
     | Confirm
     |===================================================== */

    async function confirmAction(
        action,
        payload = {}
    ){

        if(!action.confirm){

            return true;
        }

        /*
        |--------------------------------------------------------------------------
        | Bora alert
        |--------------------------------------------------------------------------
        */

        if(window.alertBora?.confirm){

            return await alertBora.confirm(

                action.confirmMessage
                || `Confirm ${action.label}?`
            );
        }

        return confirm(
            action.confirmMessage
            || `Confirm ${action.label}?`
        );
    }

    /* =====================================================
     | Execute
     |===================================================== */

    async function execute(
        grid,
        name,
        payload = {}
    ){

        const action =
            get(name);

        if(!action){

            throw new Error(

                `[grids.actions] Action "${name}" not found`
            );
        }

        /*
        |--------------------------------------------------------------------------
        | Visibility
        |--------------------------------------------------------------------------
        */

        if(
            action.visible &&
            !action.visible(
                grid,
                payload
            )
        ){

            return false;
        }

        /*
        |--------------------------------------------------------------------------
        | Enabled
        |--------------------------------------------------------------------------
        */

        if(
            action.enabled &&
            !action.enabled(
                grid,
                payload
            )
        ){

            return false;
        }

        /*
        |--------------------------------------------------------------------------
        | Confirm
        |--------------------------------------------------------------------------
        */

        const confirmed =
            await confirmAction(
                action,
                payload
            );

        if(!confirmed){

            return false;
        }

        /*
        |--------------------------------------------------------------------------
        | Events
        |--------------------------------------------------------------------------
        */

        grid.emit(

            'action.before',

            {

                action,

                payload
            }
        );

        let result = null;

        try {

            /*
            |--------------------------------------------------------------------------
            | Execute
            |--------------------------------------------------------------------------
            */

            if(action.handler){

                result =
                    await action.handler(

                        grid,

                        payload
                    );
            }

            /*
            |--------------------------------------------------------------------------
            | Success
            |--------------------------------------------------------------------------
            */

            grid.emit(

                'action.success',

                {

                    action,

                    payload,

                    result
                }
            );

        } catch(err){

            console.error(

                `[grids.actions] ${name} failed`,

                err
            );

            /*
            |--------------------------------------------------------------------------
            | Error
            |--------------------------------------------------------------------------
            */

            grid.emit(

                'action.error',

                {

                    action,

                    payload,

                    error: err
                }
            );

            throw err;
        }

        /*
        |--------------------------------------------------------------------------
        | Complete
        |--------------------------------------------------------------------------
        */

        grid.emit(

            'action.after',

            {

                action,

                payload,

                result
            }
        );

        return result;
    }

    /* =====================================================
     | Bulk Actions
     |===================================================== */

    async function bulk(
        grid,
        name,
        payload = {}
    ){

        const ids =
            selection.all(grid);

        return execute(

            grid,

            name,

            {

                ...payload,

                ids
            }
        );
    }

    return {

        register,

        get,

        exists,

        all,

        remove,

        execute,

        bulk,

        confirm: confirmAction
    };

});