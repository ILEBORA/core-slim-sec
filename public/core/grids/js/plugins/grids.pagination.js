__BORA_REGISTER_PLUGIN__('grids.pagination', async function(scope){

    const transport =
        await scope.getService(
            'grids.transport'
        );

    const state =
        await scope.getService(
            'grids.state'
        );

    /* =====================================================
     | Helpers
     |===================================================== */

    function getPage(el){

        return parseInt(

            el.dataset.gridPage || 1,

            10
        );
    }

    function loading(
        grid,
        status = true
    ){

        if(!grid.element){

            return;
        }

        grid.element.classList.toggle(

            'grid-loading',

            status
        );
    }

    /* =====================================================
     | Bindings
     |===================================================== */

    function bindPageButtons(grid){

        grid.element?.addEventListener(

            'click',

            async event => {

                const button =
                    event.target.closest(
                        '[data-grid-page]'
                    );

                if(!button){

                    return;
                }

                event.preventDefault();

                const page =
                    getPage(button);

                /*
                |--------------------------------------------------------------------------
                | Ignore active page
                |--------------------------------------------------------------------------
                */

                if(
                    page === grid.state.page
                ){

                    return;
                }

                /*
                |--------------------------------------------------------------------------
                | Events
                |--------------------------------------------------------------------------
                */

                grid.emit(

                    'pagination.before',

                    {

                        page
                    }
                );

                /*
                |--------------------------------------------------------------------------
                | Loading
                |--------------------------------------------------------------------------
                */

                loading(
                    grid,
                    true
                );

                try {

                    /*
                    |--------------------------------------------------------------------------
                    | State
                    |--------------------------------------------------------------------------
                    */

                    state.setPage(
                        grid,
                        page
                    );

                    /*
                    |--------------------------------------------------------------------------
                    | Transport
                    |--------------------------------------------------------------------------
                    */

                    await transport.page(
                        grid,
                        page
                    );

                    /*
                    |--------------------------------------------------------------------------
                    | Events
                    |--------------------------------------------------------------------------
                    */

                    grid.emit(

                        'pagination.changed',

                        {

                            page
                        }
                    );

                } catch(err){

                    console.error(

                        '[grids.pagination] page failed',

                        err
                    );

                    grid.emit(

                        'pagination.error',

                        {

                            page,

                            error: err
                        }
                    );

                } finally {

                    loading(
                        grid,
                        false
                    );
                }
            }
        );
    }

    function bindNextPrev(grid){

        grid.element?.addEventListener(

            'click',

            async event => {

                /*
                |--------------------------------------------------------------------------
                | Next
                |--------------------------------------------------------------------------
                */

                const next =
                    event.target.closest(
                        '[data-grid-next]'
                    );

                if(next){

                    event.preventDefault();

                    return transport.page(

                        grid,

                        grid.state.page + 1
                    );
                }

                /*
                |--------------------------------------------------------------------------
                | Prev
                |--------------------------------------------------------------------------
                */

                const prev =
                    event.target.closest(
                        '[data-grid-prev]'
                    );

                if(prev){

                    event.preventDefault();

                    return transport.page(

                        grid,

                        Math.max(
                            1,
                            grid.state.page - 1
                        )
                    );
                }
            }
        );
    }

    /* =====================================================
     | Lifecycle
     |===================================================== */

    async function mount(grid){

        if(!grid.element){

            return;
        }

        bindPageButtons(grid);

        bindNextPrev(grid);

        /*
        |--------------------------------------------------------------------------
        | Rebind after DOM replacement
        |--------------------------------------------------------------------------
        */

        grid.on(

            'dom.replaced',

            () => {

                bindPageButtons(grid);

                bindNextPrev(grid);
            }
        );

        /*
        |--------------------------------------------------------------------------
        | Mounted
        |--------------------------------------------------------------------------
        */

        grid.emit(

            'pagination.mounted',

            {

                page: grid.state.page
            }
        );
    }

    async function unmount(grid){

        grid.emit(
            'pagination.unmounted'
        );
    }

    return {

        compatible:[
            'table',
            'cards',
            'timeline',
            'feed',
            'mobile',
            'kanban'
        ],

        mount,

        unmount
    };

});