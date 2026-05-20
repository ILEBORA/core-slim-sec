__BORA_REGISTER_PLUGIN__('renderers.timeline', async function(scope){

    const transport =
        await scope.getService(
            'grids.transport'
        );

    const realtime =
        await scope.getService(
            'realtime.sse'
        );

    /* =====================================================
     | Config
     |===================================================== */

    const DEFAULTS = {

        infinite: true,

        autoScroll: false,

        liveInsert: true,

        threshold: 300
    };

    /* =====================================================
     | Helpers
     |===================================================== */

    function getTimeline(grid){

        return grid.element?.querySelector(
            '.grid-timeline'
        );
    }

    function getItems(grid){

        return grid.element?.querySelectorAll(
            '.timeline-item[data-row-id]'
        ) || [];
    }

    function getLastItem(grid){

        return getItems(grid)?.[
            getItems(grid).length - 1
        ];
    }

    function loading(
        grid,
        status = true
    ){

        grid.element?.classList.toggle(

            'timeline-loading',

            status
        );
    }

    /* =====================================================
     | Infinite Scroll
     |===================================================== */

    async function loadMore(grid){

        if(grid.__timelineLoading){

            return;
        }

        grid.__timelineLoading = true;

        loading(
            grid,
            true
        );

        try {

            /*
            |--------------------------------------------------------------------------
            | Transport append mode
            |--------------------------------------------------------------------------
            */

            await transport.append(

                grid,

                {

                    cursor:
                        getLastItem(grid)
                        ?.dataset
                        ?.rowId
                }
            );

            grid.emit(
                'timeline.loaded.more'
            );

        } catch(err){

            console.error(

                '[timeline] loadMore failed',

                err
            );

        } finally {

            grid.__timelineLoading =
                false;

            loading(
                grid,
                false
            );
        }
    }

    /* =====================================================
     | Scroll Detection
     |===================================================== */

    function bindScroll(grid){

        if(
            !grid.__timelineOptions
                ?.infinite
        ){

            return;
        }

        const container =
            getTimeline(grid);

        if(!container){

            return;
        }

        container.addEventListener(

            'scroll',

            () => {

                const remaining =

                    container.scrollHeight

                    - container.scrollTop

                    - container.clientHeight;

                if(

                    remaining

                    < grid.__timelineOptions
                        .threshold
                ){

                    loadMore(grid);
                }
            }
        );
    }

    /* =====================================================
     | Live Insert
     |===================================================== */

    function bindRealtime(grid){

        if(
            !grid.__timelineOptions
                ?.liveInsert
        ){

            return;
        }

        realtime.on(

            'timeline.item.created',

            async payload => {

                if(
                    payload.grid !== grid.id
                ){

                    return;
                }

                /*
                |--------------------------------------------------------------------------
                | Prepend item
                |--------------------------------------------------------------------------
                */

                await transport.prepend(

                    grid,

                    payload
                );

                grid.emit(

                    'timeline.item.inserted',

                    payload
                );
            }
        );
    }

    /* =====================================================
     | Auto Scroll
     |===================================================== */

    function scrollBottom(grid){

        const container =
            getTimeline(grid);

        if(!container){

            return;
        }

        container.scrollTop =
            container.scrollHeight;
    }

    /* =====================================================
     | Group Separators
     |===================================================== */

    function groupDates(grid){

        const groups =
            grid.element?.querySelectorAll(

                '[data-date-group]'
            ) || [];

        groups.forEach(group => {

            if(
                !group.querySelector(
                    '.timeline-group-label'
                )
            ){

                const label =
                    document.createElement(
                        'div'
                    );

                label.className =
                    'timeline-group-label';

                label.innerText =
                    group.dataset.dateGroup;

                group.prepend(label);
            }
        });
    }

    /* =====================================================
     | Density
     |===================================================== */

    function setDensity(
        grid,
        density = 'normal'
    ){

        const timeline =
            getTimeline(grid);

        if(!timeline){

            return;
        }

        timeline.classList.remove(

            'density-compact',

            'density-normal',

            'density-comfortable'
        );

        timeline.classList.add(

            `density-${density}`
        );

        grid.emit(

            'timeline.density.changed',

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

        grid.__timelineOptions = {

            ...DEFAULTS,

            ...options
        };

        bindScroll(grid);

        bindRealtime(grid);

        groupDates(grid);

        /*
        |--------------------------------------------------------------------------
        | Auto scroll
        |--------------------------------------------------------------------------
        */

        if(
            grid.__timelineOptions
                ?.autoScroll
        ){

            scrollBottom(grid);
        }

        /*
        |--------------------------------------------------------------------------
        | DOM replacement
        |--------------------------------------------------------------------------
        */

        grid.on(

            'dom.replaced',

            () => {

                bindScroll(grid);

                groupDates(grid);
            }
        );

        /*
        |--------------------------------------------------------------------------
        | Mounted
        |--------------------------------------------------------------------------
        */

        grid.emit(
            'timeline.mounted'
        );
    }

    async function unmount(grid){

        grid.emit(
            'timeline.unmounted'
        );
    }

    return {

        compatible:[
            'timeline',
            'feed'
        ],

        mount,

        unmount,

        loadMore,

        setDensity,

        scrollBottom
    };

});