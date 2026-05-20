__BORA_REGISTER_PLUGIN__('grids.contextmenu', async function(scope){

    const actions =
        await scope.getService(
            'grids.actions'
        );

    const selection =
        await scope.getService(
            'grids.selection'
        );

    /*
    |--------------------------------------------------------------------------
    | Replace with your actual context menu service
    |--------------------------------------------------------------------------
    */

    const contextMenu =
        await scope.getPlugin(
            'ui.context.menu'
        );

    /* =====================================================
     | Helpers
     |===================================================== */

    function getContextTarget(event){

        return event.target.closest(

            '[data-context-id]'
        );
    }

    function getContext(target){

        if(!target){

            return null;
        }

        return {

            id:
                target.dataset.contextId,

            type:
                target.dataset.contextType,

            row:
                target.dataset.rowId,

            element: target
        };
    }

    function ensureSelection(
        grid,
        context
    ){

        if(!context?.id){

            return;
        }

        /*
        |--------------------------------------------------------------------------
        | Auto select clicked row/card
        |--------------------------------------------------------------------------
        */

        if(
            !selection.isSelected(
                grid,
                context.id
            )
        ){

            selection.clear(grid);

            selection.select(
                grid,
                context.id
            );
        }
    }

    function buildMenuPayload(
        grid,
        context
    ){

        return {

            grid,

            context,

            selected:
                selection.all(grid)
        };
    }

    /* =====================================================
     | Open Menu
     |===================================================== */

    async function open(
        grid,
        event
    ){

        const target =
            getContextTarget(event);

        if(!target){

            return;
        }

        event.preventDefault();

        /*
        |--------------------------------------------------------------------------
        | Context
        |--------------------------------------------------------------------------
        */

        const context =
            getContext(target);

        /*
        |--------------------------------------------------------------------------
        | Selection sync
        |--------------------------------------------------------------------------
        */

        ensureSelection(
            grid,
            context
        );

        /*
        |--------------------------------------------------------------------------
        | Payload
        |--------------------------------------------------------------------------
        */

        const payload =
            buildMenuPayload(
                grid,
                context
            );

        /*
        |--------------------------------------------------------------------------
        | Events
        |--------------------------------------------------------------------------
        */

        grid.emit(

            'contextmenu.before',

            payload
        );

        /*
        |--------------------------------------------------------------------------
        | Menu
        |--------------------------------------------------------------------------
        */

        if(contextMenu?.open){

            await contextMenu.open({

                x: event.clientX,

                y: event.clientY,

                context: payload
            });
        }

        /*
        |--------------------------------------------------------------------------
        | Events
        |--------------------------------------------------------------------------
        */

        grid.emit(

            'contextmenu.opened',

            payload
        );
    }

    /* =====================================================
     | Action Delegation
     |===================================================== */

    async function executeAction(
        grid,
        name,
        payload = {}
    ){

        return actions.execute(

            grid,

            name,

            payload
        );
    }

    /* =====================================================
     | Bindings
     |===================================================== */

    function bindContextMenu(grid){

        grid.element?.addEventListener(

            'contextmenu',

            event => {

                open(
                    grid,
                    event
                );
            }
        );
    }

    /*
    |--------------------------------------------------------------------------
    | Optional trigger button support
    |--------------------------------------------------------------------------
    */

    function bindTriggers(grid){

        grid.element?.addEventListener(

            'click',

            event => {

                const trigger =
                    event.target.closest(

                        '[data-context-trigger]'
                    );

                if(!trigger){

                    return;
                }

                event.preventDefault();

                open(
                    grid,
                    {

                        ...event,

                        target: trigger
                    }
                );
            }
        );
    }

    /* =====================================================
     | Lifecycle
     |===================================================== */

    async function mount(grid){

        bindContextMenu(grid);

        bindTriggers(grid);

        /*
        |--------------------------------------------------------------------------
        | Rebind after DOM replacement
        |--------------------------------------------------------------------------
        */

        grid.on(

            'dom.replaced',

            () => {

                bindContextMenu(grid);

                bindTriggers(grid);
            }
        );

        /*
        |--------------------------------------------------------------------------
        | Events
        |--------------------------------------------------------------------------
        */

        grid.emit(
            'contextmenu.mounted'
        );
    }

    async function unmount(grid){

        grid.emit(
            'contextmenu.unmounted'
        );
    }

    return {

        compatible:[
            'table',
            'cards',
            'feed',
            'kanban',
            'mobile',
            'timeline'
        ],

        mount,

        unmount,

        open,

        executeAction
    };

});