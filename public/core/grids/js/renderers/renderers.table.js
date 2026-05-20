__BORA_REGISTER_PLUGIN__('renderers.table', async function(scope){

    const selection =
        await scope.getService(
            'grids.selection'
        );

    /* =====================================================
     | Config
     |===================================================== */

    const DEFAULTS = {

        stickyHeader: true,

        hover: true,

        density: 'normal'
    };

    /* =====================================================
     | Helpers
     |===================================================== */

    function getTable(grid){

        return grid.element?.querySelector(
            'table'
        );
    }

    function getRows(grid){

        return grid.element?.querySelectorAll(
            '[data-row-id]'
        ) || [];
    }

    function getWrapper(grid){

        return grid.element?.querySelector(
            '.grid-table-wrapper'
        );
    }

    /* =====================================================
     | Responsive Wrapper
     |===================================================== */

    function ensureWrapper(grid){

        const table =
            getTable(grid);

        if(!table){

            return;
        }

        /*
        |--------------------------------------------------------------------------
        | Already wrapped
        |--------------------------------------------------------------------------
        */

        if(
            table.parentElement.classList.contains(
                'grid-table-wrapper'
            )
        ){

            return;
        }

        const wrapper =
            document.createElement('div');

        wrapper.className =
            'grid-table-wrapper';

        table.parentNode.insertBefore(
            wrapper,
            table
        );

        wrapper.appendChild(table);
    }

    /* =====================================================
     | Sticky Header
     |===================================================== */

    function applyStickyHeader(grid){

        if(
            !grid.__tableOptions
                ?.stickyHeader
        ){

            return;
        }

        const header =
            grid.element?.querySelector(
                'thead'
            );

        if(!header){

            return;
        }

        header.classList.add(
            'grid-sticky-header'
        );
    }

    /* =====================================================
     | Density
     |===================================================== */

    function applyDensity(grid){

        const table =
            getTable(grid);

        if(!table){

            return;
        }

        table.classList.remove(

            'density-compact',

            'density-normal',

            'density-comfortable'
        );

        table.classList.add(

            `density-${
                grid.__tableOptions.density
            }`
        );
    }

    /* =====================================================
     | Hover
     |===================================================== */

    function bindHover(grid){

        if(
            !grid.__tableOptions.hover
        ){

            return;
        }

        getRows(grid).forEach(row => {

            row.addEventListener(

                'mouseenter',

                () => {

                    row.classList.add(
                        'hover'
                    );
                }
            );

            row.addEventListener(

                'mouseleave',

                () => {

                    row.classList.remove(
                        'hover'
                    );
                }
            );
        });
    }

    /* =====================================================
     | Row Click
     |===================================================== */

    function bindRows(grid){

        grid.element?.addEventListener(

            'click',

            event => {

                const row =
                    event.target.closest(
                        '[data-row-id]'
                    );

                if(!row){

                    return;
                }

                /*
                |--------------------------------------------------------------------------
                | Ignore controls
                |--------------------------------------------------------------------------
                */

                if(
                    event.target.closest(

                        'button, a, input, select, textarea'
                    )
                ){

                    return;
                }

                /*
                |--------------------------------------------------------------------------
                | Selection
                |--------------------------------------------------------------------------
                */

                selection.toggle(

                    grid,

                    row.dataset.rowId
                );

                /*
                |--------------------------------------------------------------------------
                | Events
                |--------------------------------------------------------------------------
                */

                grid.emit(

                    'table.row.clicked',

                    {

                        row:
                            row.dataset.rowId,

                        element: row
                    }
                );
            }
        );
    }

    /* =====================================================
     | Selection Sync
     |===================================================== */

    function syncSelection(grid){

        getRows(grid).forEach(row => {

            row.classList.toggle(

                'selected',

                selection.isSelected(

                    grid,

                    row.dataset.rowId
                )
            );
        });
    }

    /* =====================================================
     | Overflow Detection
     |===================================================== */

    function detectOverflow(grid){

        const wrapper =
            getWrapper(grid);

        if(!wrapper){

            return;
        }

        wrapper.classList.toggle(

            'overflowing',

            wrapper.scrollWidth >
            wrapper.clientWidth
        );
    }

    /* =====================================================
     | Public API
     |===================================================== */

    function setDensity(
        grid,
        density = 'normal'
    ){

        grid.__tableOptions.density =
            density;

        applyDensity(grid);

        grid.emit(

            'table.density.changed',

            {

                density
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

        grid.__tableOptions = {

            ...DEFAULTS,

            ...options
        };

        ensureWrapper(grid);

        applyStickyHeader(grid);

        applyDensity(grid);

        bindHover(grid);

        bindRows(grid);

        syncSelection(grid);

        detectOverflow(grid);

        /*
        |--------------------------------------------------------------------------
        | Selection sync
        |--------------------------------------------------------------------------
        */

        grid.on(

            'selection.changed',

            () => {

                syncSelection(grid);
            }
        );

        /*
        |--------------------------------------------------------------------------
        | DOM replacement
        |--------------------------------------------------------------------------
        */

        grid.on(

            'dom.replaced',

            () => {

                ensureWrapper(grid);

                applyStickyHeader(grid);

                applyDensity(grid);

                bindHover(grid);

                bindRows(grid);

                syncSelection(grid);

                detectOverflow(grid);
            }
        );

        /*
        |--------------------------------------------------------------------------
        | Resize
        |--------------------------------------------------------------------------
        */

        window.addEventListener(

            'resize',

            () => {

                detectOverflow(grid);
            }
        );

        /*
        |--------------------------------------------------------------------------
        | Mounted
        |--------------------------------------------------------------------------
        */

        grid.emit(
            'table.mounted'
        );
    }

    async function unmount(grid){

        grid.emit(
            'table.unmounted'
        );
    }

    return {

        compatible:[
            'table'
        ],

        mount,

        unmount,

        setDensity
    };

});