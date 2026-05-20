__BORA_REGISTER_PLUGIN__('renderers.feed', async function(scope){

    const actions =
        await scope.getService(
            'grids.actions'
        );

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

        liveInsert: true,

        lazyMedia: true,

        threshold: 300
    };

    /* =====================================================
     | Helpers
     |===================================================== */

    function getFeed(grid){

        return grid.element?.querySelector(
            '.grid-feed'
        );
    }

    function getItems(grid){

        return grid.element?.querySelectorAll(
            '.feed-item[data-row-id]'
        ) || [];
    }

    function loading(
        grid,
        status = true
    ){

        grid.element?.classList.toggle(

            'feed-loading',

            status
        );
    }

    /* =====================================================
     | Infinite Scroll
     |===================================================== */

    async function loadMore(grid){

        if(grid.__feedLoading){

            return;
        }

        grid.__feedLoading = true;

        loading(
            grid,
            true
        );

        try {

            const last =
                getItems(grid)?.[
                    getItems(grid).length - 1
                ];

            await transport.append(

                grid,

                {

                    cursor:
                        last?.dataset?.rowId
                }
            );

            grid.emit(
                'feed.loaded.more'
            );

        } catch(err){

            console.error(

                '[feed] loadMore failed',

                err
            );

        } finally {

            grid.__feedLoading = false;

            loading(
                grid,
                false
            );
        }
    }

    /* =====================================================
     | Scroll
     |===================================================== */

    function bindScroll(grid){

        if(
            !grid.__feedOptions
                ?.infinite
        ){

            return;
        }

        const feed =
            getFeed(grid);

        if(!feed){

            return;
        }

        feed.addEventListener(

            'scroll',

            () => {

                const remaining =

                    feed.scrollHeight

                    - feed.scrollTop

                    - feed.clientHeight;

                if(

                    remaining

                    < grid.__feedOptions
                        .threshold
                ){

                    loadMore(grid);
                }
            }
        );
    }

    /* =====================================================
     | Reactions
     |===================================================== */

    function bindActions(grid){

        grid.element?.addEventListener(

            'click',

            async event => {

                const button =
                    event.target.closest(
                        '[data-feed-action]'
                    );

                if(!button){

                    return;
                }

                const item =
                    button.closest(
                        '.feed-item'
                    );

                if(!item){

                    return;
                }

                const action =
                    button.dataset.feedAction;

                const row =
                    item.dataset.rowId;

                /*
                |--------------------------------------------------------------------------
                | Loading
                |--------------------------------------------------------------------------
                */

                button.disabled = true;

                try {

                    await actions.execute(

                        grid,

                        `feed.${action}`,

                        {

                            row
                        }
                    );

                    /*
                    |--------------------------------------------------------------------------
                    | Patch item
                    |--------------------------------------------------------------------------
                    */

                    await transport.refreshRow(

                        grid,

                        row
                    );

                    grid.emit(

                        'feed.action.executed',

                        {

                            action,

                            row
                        }
                    );

                } catch(err){

                    console.error(

                        '[feed] action failed',

                        err
                    );

                } finally {

                    button.disabled = false;
                }
            }
        );
    }

    /* =====================================================
     | Lazy Media
     |===================================================== */

    function hydrateMedia(grid){

        if(
            !grid.__feedOptions
                ?.lazyMedia
        ){

            return;
        }

        const media =
            grid.element?.querySelectorAll(

                '[data-feed-media][data-src]'
            ) || [];

        const observer =
            new IntersectionObserver(

                entries => {

                    entries.forEach(entry => {

                        if(
                            !entry.isIntersecting
                        ){

                            return;
                        }

                        const el =
                            entry.target;

                        const src =
                            el.dataset.src;

                        if(src){

                            el.src = src;
                        }

                        observer.unobserve(el);
                    });
                }
            );

        media.forEach(el => {

            observer.observe(el);
        });
    }

    /* =====================================================
     | Live Inserts
     |===================================================== */

    function bindRealtime(grid){

        if(
            !grid.__feedOptions
                ?.liveInsert
        ){

            return;
        }

        realtime.on(

            'feed.item.created',

            async payload => {

                if(
                    payload.grid !== grid.id
                ){

                    return;
                }

                await transport.prepend(

                    grid,

                    payload
                );

                grid.emit(

                    'feed.item.inserted',

                    payload
                );
            }
        );
    }

    /* =====================================================
     | Density
     |===================================================== */

    function setDensity(
        grid,
        density = 'normal'
    ){

        const feed =
            getFeed(grid);

        if(!feed){

            return;
        }

        feed.classList.remove(

            'density-compact',

            'density-normal',

            'density-comfortable'
        );

        feed.classList.add(

            `density-${density}`
        );

        grid.emit(

            'feed.density.changed',

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

        grid.__feedOptions = {

            ...DEFAULTS,

            ...options
        };

        bindScroll(grid);

        bindActions(grid);

        bindRealtime(grid);

        hydrateMedia(grid);

        /*
        |--------------------------------------------------------------------------
        | DOM replacement
        |--------------------------------------------------------------------------
        */

        grid.on(

            'dom.replaced',

            () => {

                bindScroll(grid);

                bindActions(grid);

                hydrateMedia(grid);
            }
        );

        /*
        |--------------------------------------------------------------------------
        | Mounted
        |--------------------------------------------------------------------------
        */

        grid.emit(
            'feed.mounted'
        );
    }

    async function unmount(grid){

        grid.emit(
            'feed.unmounted'
        );
    }

    return {

        compatible:[
            'feed'
        ],

        mount,

        unmount,

        loadMore,

        setDensity
    };

});