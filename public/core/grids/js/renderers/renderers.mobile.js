__BORA_REGISTER_PLUGIN__('renderers.mobile', async function(scope){

    const selection =
        await scope.getService(
            'grids.selection'
        );

    const actions =
        await scope.getService(
            'grids.actions'
        );

    /* =====================================================
     | Config
     |===================================================== */

    const DEFAULTS = {

        compact: true,

        touch: true,

        swipe: false,

        autoCollapse: true
    };

    /* =====================================================
     | Helpers
     |===================================================== */

    function getItems(grid){

        return grid.element?.querySelectorAll(
            '.mobile-item[data-row-id]'
        ) || [];
    }

    function isMobile(){

        return window.innerWidth < 768;
    }

    /* =====================================================
     | Compact
     |===================================================== */

    function applyCompact(grid){

        grid.element?.classList.toggle(

            'mobile-compact',

            !!grid.__mobileOptions.compact
        );
    }

    /* =====================================================
     | Selection Sync
     |===================================================== */

    function syncSelection(grid){

        getItems(grid).forEach(item => {

            item.classList.toggle(

                'selected',

                selection.isSelected(

                    grid,

                    item.dataset.rowId
                )
            );
        });
    }

    /* =====================================================
     | Item Click
     |===================================================== */

    function bindItems(grid){

        grid.element?.addEventListener(

            'click',

            event => {

                const item =
                    event.target.closest(
                        '.mobile-item'
                    );

                if(!item){

                    return;
                }

                /*
                |--------------------------------------------------------------------------
                | Ignore controls
                |--------------------------------------------------------------------------
                */

                if(
                    event.target.closest(

                        'button, a, input, textarea'
                    )
                ){

                    return;
                }

                selection.toggle(

                    grid,

                    item.dataset.rowId
                );

                grid.emit(

                    'mobile.item.clicked',

                    {

                        row:
                            item.dataset.rowId,

                        element: item
                    }
                );
            }
        );
    }

    /* =====================================================
     | Touch Support
     |===================================================== */

    function bindTouch(grid){

        if(
            !grid.__mobileOptions
                ?.touch
        ){

            return;
        }

        getItems(grid).forEach(item => {

            item.addEventListener(

                'touchstart',

                () => {

                    item.classList.add(
                        'touching'
                    );
                }
            );

            item.addEventListener(

                'touchend',

                () => {

                    item.classList.remove(
                        'touching'
                    );
                }
            );
        });
    }

    /* =====================================================
     | Swipe Actions
     |===================================================== */

    function bindSwipe(grid){

        if(
            !grid.__mobileOptions
                ?.swipe
        ){

            return;
        }

        getItems(grid).forEach(item => {

            let startX = 0;

            item.addEventListener(

                'touchstart',

                event => {

                    startX =
                        event.touches[0].clientX;
                }
            );

            item.addEventListener(

                'touchend',

                async event => {

                    const endX =
                        event.changedTouches[0]
                            .clientX;

                    const diff =
                        endX - startX;

                    /*
                    |--------------------------------------------------------------------------
                    | Swipe right
                    |--------------------------------------------------------------------------
                    */

                    if(diff > 100){

                        grid.emit(

                            'mobile.swipe.right',

                            {

                                row:
                                    item.dataset.rowId
                            }
                        );

                        return;
                    }

                    /*
                    |--------------------------------------------------------------------------
                    | Swipe left
                    |--------------------------------------------------------------------------
                    */

                    if(diff < -100){

                        grid.emit(

                            'mobile.swipe.left',

                            {

                                row:
                                    item.dataset.rowId
                            }
                        );
                    }
                }
            );
        });
    }

    /* =====================================================
     | Auto Collapse
     |===================================================== */

    function autoCollapse(grid){

        if(
            !grid.__mobileOptions
                ?.autoCollapse
        ){

            return;
        }

        grid.element?.classList.toggle(

            'mobile-mode',

            isMobile()
        );
    }

    /* =====================================================
     | Responsive
     |===================================================== */

    function bindResize(grid){

        window.addEventListener(

            'resize',

            () => {

                autoCollapse(grid);
            }
        );
    }

    /* =====================================================
     | Context Actions
     |===================================================== */

    function bindLongPress(grid){

        let timer = null;

        getItems(grid).forEach(item => {

            item.addEventListener(

                'touchstart',

                () => {

                    timer = setTimeout(

                        async () => {

                            await actions.execute(

                                grid,

                                'mobile.context',

                                {

                                    row:
                                        item.dataset
                                            .rowId
                                }
                            );

                            grid.emit(

                                'mobile.longpress',

                                {

                                    row:
                                        item.dataset
                                            .rowId
                                }
                            );

                        },

                        600
                    );
                }
            );

            item.addEventListener(

                'touchend',

                () => {

                    clearTimeout(timer);
                }
            );
        });
    }

    /* =====================================================
     | Lifecycle
     |===================================================== */

    async function mount(
        grid,
        options = {}
    ){

        grid.__mobileOptions = {

            ...DEFAULTS,

            ...options
        };

        applyCompact(grid);

        autoCollapse(grid);

        bindItems(grid);

        bindTouch(grid);

        bindSwipe(grid);

        bindLongPress(grid);

        bindResize(grid);

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

                bindItems(grid);

                bindTouch(grid);

                bindSwipe(grid);

                bindLongPress(grid);

                syncSelection(grid);
            }
        );

        /*
        |--------------------------------------------------------------------------
        | Mounted
        |--------------------------------------------------------------------------
        */

        grid.emit(
            'mobile.mounted'
        );
    }

    async function unmount(grid){

        grid.emit(
            'mobile.unmounted'
        );
    }

    return {

        compatible:[
            'mobile'
        ],

        mount,

        unmount
    };

});