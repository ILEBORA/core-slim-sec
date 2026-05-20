__BORA_REGISTER_PLUGIN__('grids.inlineedit', async function(scope){

    const transport =
        await scope.getService(
            'grids.transport'
        );

    const actions =
        await scope.getService(
            'grids.actions'
        );

    /* =====================================================
     | Config
     |===================================================== */

    const DEFAULTS = {

        trigger: 'dblclick'
    };

    /* =====================================================
     | Helpers
     |===================================================== */

    function getEditable(target){

        return target.closest(
            '[data-editable]'
        );
    }

    function getContext(element){

        return {

            row:
                element.dataset.rowId,

            column:
                element.dataset.column,

            value:
                element.innerText.trim(),

            element
        };
    }

    function isEditing(element){

        return element.dataset.editing === '1';
    }

    function setEditing(
        element,
        status = true
    ){

        element.dataset.editing =
            status ? '1' : '0';

        element.classList.toggle(
            'editing',
            status
        );
    }

    function createInput(
        context
    ){

        const input =
            document.createElement('input');

        input.type = 'text';

        input.value = context.value;

        input.className =
            'grid-inline-input';

        return input;
    }

    /* =====================================================
     | Edit Mode
     |===================================================== */

    async function activate(
        grid,
        element
    ){

        if(
            !element ||
            isEditing(element)
        ){

            return;
        }

        const context =
            getContext(element);

        /*
        |--------------------------------------------------------------------------
        | Events
        |--------------------------------------------------------------------------
        */

        grid.emit(

            'inlineedit.before',

            context
        );

        /*
        |--------------------------------------------------------------------------
        | State
        |--------------------------------------------------------------------------
        */

        setEditing(
            element,
            true
        );

        /*
        |--------------------------------------------------------------------------
        | Original content
        |--------------------------------------------------------------------------
        */

        const original =
            element.innerHTML;

        /*
        |--------------------------------------------------------------------------
        | Input
        |--------------------------------------------------------------------------
        */

        const input =
            createInput(context);

        element.innerHTML = '';

        element.appendChild(input);

        input.focus();

        input.select();

        /*
        |--------------------------------------------------------------------------
        | Save
        |--------------------------------------------------------------------------
        */

        async function save(){

            const value =
                input.value;

            /*
            |--------------------------------------------------------------------------
            | Loading
            |--------------------------------------------------------------------------
            */

            element.classList.add(
                'saving'
            );

            try {

                /*
                |--------------------------------------------------------------------------
                | Execute action
                |--------------------------------------------------------------------------
                */

                await actions.execute(

                    grid,

                    'inlineedit.save',

                    {

                        row:
                            context.row,

                        column:
                            context.column,

                        value
                    }
                );

                /*
                |--------------------------------------------------------------------------
                | Refresh cell
                |--------------------------------------------------------------------------
                */

                await transport.refreshCell(

                    grid,

                    context.row,

                    context.column
                );

                /*
                |--------------------------------------------------------------------------
                | Events
                |--------------------------------------------------------------------------
                */

                grid.emit(

                    'inlineedit.saved',

                    {

                        ...context,

                        value
                    }
                );

            } catch(err){

                console.error(

                    '[grids.inlineedit] save failed',

                    err
                );

                element.innerHTML =
                    original;

                grid.emit(

                    'inlineedit.error',

                    {

                        ...context,

                        error: err
                    }
                );

            } finally {

                setEditing(
                    element,
                    false
                );

                element.classList.remove(
                    'saving'
                );
            }
        }

        /*
        |--------------------------------------------------------------------------
        | Cancel
        |--------------------------------------------------------------------------
        */

        function cancel(){

            element.innerHTML =
                original;

            setEditing(
                element,
                false
            );

            grid.emit(

                'inlineedit.cancelled',

                context
            );
        }

        /*
        |--------------------------------------------------------------------------
        | Keyboard
        |--------------------------------------------------------------------------
        */

        input.addEventListener(

            'keydown',

            async event => {

                /*
                |--------------------------------------------------------------------------
                | Enter
                |--------------------------------------------------------------------------
                */

                if(event.key === 'Enter'){

                    event.preventDefault();

                    return save();
                }

                /*
                |--------------------------------------------------------------------------
                | Escape
                |--------------------------------------------------------------------------
                */

                if(event.key === 'Escape'){

                    event.preventDefault();

                    return cancel();
                }
            }
        );

        /*
        |--------------------------------------------------------------------------
        | Blur autosave
        |--------------------------------------------------------------------------
        */

        input.addEventListener(

            'blur',

            () => {

                save();
            }
        );

        /*
        |--------------------------------------------------------------------------
        | Events
        |--------------------------------------------------------------------------
        */

        grid.emit(

            'inlineedit.activated',

            context
        );
    }

    /* =====================================================
     | Bindings
     |===================================================== */

    function bind(grid){

        grid.element?.addEventListener(

            grid.__inlineEditOptions.trigger,

            event => {

                const editable =
                    getEditable(
                        event.target
                    );

                if(!editable){

                    return;
                }

                activate(
                    grid,
                    editable
                );
            }
        );
    }

    /* =====================================================
     | Lifecycle
     |===================================================== */

    async function mount(
        grid,
        options = {}
    ){

        grid.__inlineEditOptions = {

            ...DEFAULTS,

            ...options
        };

        bind(grid);

        /*
        |--------------------------------------------------------------------------
        | Rebind after DOM replacement
        |--------------------------------------------------------------------------
        */

        grid.on(

            'dom.replaced',

            () => {

                bind(grid);
            }
        );

        /*
        |--------------------------------------------------------------------------
        | Events
        |--------------------------------------------------------------------------
        */

        grid.emit(
            'inlineedit.mounted'
        );
    }

    async function unmount(grid){

        grid.emit(
            'inlineedit.unmounted'
        );
    }

    return {

        compatible:[
            'table',
            'cards',
            'kanban'
        ],

        mount,

        unmount,

        activate
    };

});