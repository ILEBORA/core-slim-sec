__BORA_REGISTER_PLUGIN__('grids.table', async function(scope){

    function applyResponsive(grid){

        const table =
            grid.element?.querySelector(
                'table'
            );

        if(!table){

            return;
        }

        /*
        |--------------------------------------------------------------------------
        | Wrap table
        |--------------------------------------------------------------------------
        */

        if(
            !table.parentElement.classList.contains(
                'grid-table-responsive'
            )
        ){

            const wrapper =
                document.createElement('div');

            wrapper.className =
                'grid-table-responsive';

            table.parentNode.insertBefore(
                wrapper,
                table
            );

            wrapper.appendChild(table);
        }
    }

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

    function scanOverflow(grid){

        const wrapper =
            grid.element?.querySelector(
                '.grid-table-responsive'
            );

        if(!wrapper){

            return;
        }

        wrapper.classList.toggle(

            'overflowing',

            wrapper.scrollWidth >
            wrapper.clientWidth
        );
    }

    async function mount(grid){

        applyResponsive(grid);

        bindRows(grid);

        scanOverflow(grid);

        /*
        |--------------------------------------------------------------------------
        | Resize
        |--------------------------------------------------------------------------
        */

        window.addEventListener(

            'resize',

            () => scanOverflow(grid)
        );

        /*
        |--------------------------------------------------------------------------
        | Rebind after DOM replacement
        |--------------------------------------------------------------------------
        */

        grid.on(

            'dom.replaced',

            () => {

                applyResponsive(grid);

                bindRows(grid);

                scanOverflow(grid);
            }
        );

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

        unmount
    };

});