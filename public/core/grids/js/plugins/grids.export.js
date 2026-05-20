__BORA_REGISTER_PLUGIN__('grids.export', async function(scope){

    const state =
        await scope.getService(
            'grids.state'
        );

    function buildUrl(
        grid,
        format
    ){

        const params =
            new URLSearchParams({

                grid: grid.id,

                format,

                state: JSON.stringify(

                    state.get(grid)
                )
            });

        return (

            'api/modules/grids/export?'

            + params.toString()
        );
    }

    async function exportGrid(
        grid,
        format = 'csv'
    ){

        const url =
            buildUrl(
                grid,
                format
            );

        window.open(
            url,
            '_blank'
        );

        grid.emit(

            'export.started',

            {

                format
            }
        );
    }

    function bind(grid){

        grid.element?.addEventListener(

            'click',

            event => {

                const button =
                    event.target.closest(
                        '[data-grid-export]'
                    );

                if(!button){

                    return;
                }

                event.preventDefault();

                exportGrid(

                    grid,

                    button.dataset.gridExport
                );
            }
        );
    }

    async function mount(grid){

        bind(grid);

        grid.on(

            'dom.replaced',

            () => {

                bind(grid);
            }
        );

        grid.emit(
            'export.mounted'
        );
    }

    async function unmount(grid){

        grid.emit(
            'export.unmounted'
        );
    }

    return {

        compatible:[
            'table',
            'cards',
            'feed',
            'kanban'
        ],

        mount,

        unmount,

        export: exportGrid
    };

});