__BORA_REGISTER_PLUGIN__('renderers.cards', async function(scope){

    const selection =
        await scope.getService(
            'grids.selection'
        );

    /* =====================================================
     | Config
     |===================================================== */

    const DEFAULTS = {

        hover: true,

        compact: false,

        columns: 'auto',

        masonry: false
    };

    /* =====================================================
     | Helpers
     |===================================================== */

    function getContainer(grid){

        return grid.element?.querySelector(
            '.grid-cards'
        );
    }

    function getCards(grid){

        return grid.element?.querySelectorAll(
            '.grid-card[data-row-id]'
        ) || [];
    }

    /* =====================================================
     | Compact Mode
     |===================================================== */

    function applyCompact(grid){

        const container =
            getContainer(grid);

        if(!container){

            return;
        }

        container.classList.toggle(

            'cards-compact',

            !!grid.__cardsOptions.compact
        );
    }

    /* =====================================================
     | Columns
     |===================================================== */

    function applyColumns(grid){

        const container =
            getContainer(grid);

        if(!container){

            return;
        }

        const columns =
            grid.__cardsOptions.columns;

        if(columns === 'auto'){

            container.style.removeProperty(
                '--grid-columns'
            );

            return;
        }

        container.style.setProperty(

            '--grid-columns',

            columns
        );
    }

    /* =====================================================
     | Hover
     |===================================================== */

    function bindHover(grid){

        if(
            !grid.__cardsOptions.hover
        ){

            return;
        }

        getCards(grid).forEach(card => {

            card.addEventListener(

                'mouseenter',

                () => {

                    card.classList.add(
                        'hover'
                    );
                }
            );

            card.addEventListener(

                'mouseleave',

                () => {

                    card.classList.remove(
                        'hover'
                    );
                }
            );
        });
    }

    /* =====================================================
     | Selection
     |===================================================== */

    function syncSelection(grid){

        getCards(grid).forEach(card => {

            card.classList.toggle(

                'selected',

                selection.isSelected(

                    grid,

                    card.dataset.rowId
                )
            );
        });
    }

    /* =====================================================
     | Card Click
     |===================================================== */

    function bindCards(grid){

        grid.element?.addEventListener(

            'click',

            event => {

                const card =
                    event.target.closest(
                        '.grid-card'
                    );

                if(!card){

                    return;
                }

                /*
                |--------------------------------------------------------------------------
                | Ignore controls
                |--------------------------------------------------------------------------
                */

                if(
                    event.target.closest(

                        'button, a, input, textarea, select'
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

                    card.dataset.rowId
                );

                /*
                |--------------------------------------------------------------------------
                | Events
                |--------------------------------------------------------------------------
                */

                grid.emit(

                    'cards.card.clicked',

                    {

                        row:
                            card.dataset.rowId,

                        element: card
                    }
                );
            }
        );
    }

    /* =====================================================
     | Masonry
     |===================================================== */

    function applyMasonry(grid){

        const container =
            getContainer(grid);

        if(!container){

            return;
        }

        container.classList.toggle(

            'cards-masonry',

            !!grid.__cardsOptions.masonry
        );
    }

    /* =====================================================
     | Public API
     |===================================================== */

    function setCompact(
        grid,
        compact = true
    ){

        grid.__cardsOptions.compact =
            compact;

        applyCompact(grid);

        grid.emit(

            'cards.compact.changed',

            {

                compact
            }
        );
    }

    function setColumns(
        grid,
        columns = 'auto'
    ){

        grid.__cardsOptions.columns =
            columns;

        applyColumns(grid);

        grid.emit(

            'cards.columns.changed',

            {

                columns
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

        grid.__cardsOptions = {

            ...DEFAULTS,

            ...options
        };

        applyCompact(grid);

        applyColumns(grid);

        applyMasonry(grid);

        bindHover(grid);

        bindCards(grid);

        syncSelection(grid);

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

                applyCompact(grid);

                applyColumns(grid);

                applyMasonry(grid);

                bindHover(grid);

                bindCards(grid);

                syncSelection(grid);
            }
        );

        /*
        |--------------------------------------------------------------------------
        | Mounted
        |--------------------------------------------------------------------------
        */

        grid.emit(
            'cards.mounted'
        );
    }

    async function unmount(grid){

        grid.emit(
            'cards.unmounted'
        );
    }

    return {

        compatible:[
            'cards',
            'feed',
            'mobile'
        ],

        mount,

        unmount,

        setCompact,

        setColumns
    };

});