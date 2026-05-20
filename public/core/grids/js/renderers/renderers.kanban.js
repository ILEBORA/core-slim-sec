__BORA_REGISTER_PLUGIN__('renderers.kanban', async function(scope){

    const actions =
        await scope.getService(
            'grids.actions'
        );

    const selection =
        await scope.getService(
            'grids.selection'
        );

    /* =====================================================
     | Config
     |===================================================== */

    const DEFAULTS = {

        draggable: true,

        collapsible: true,

        realtime: true
    };

    /* =====================================================
     | Helpers
     |===================================================== */

    function getLanes(grid){

        return grid.element?.querySelectorAll(
            '.kanban-lane[data-lane-id]'
        ) || [];
    }

    function getCards(grid){

        return grid.element?.querySelectorAll(
            '.kanban-card[data-row-id]'
        ) || [];
    }

    /* =====================================================
     | Selection Sync
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
                        '.kanban-card'
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

                        'button, a, input, textarea'
                    )
                ){

                    return;
                }

                selection.toggle(

                    grid,

                    card.dataset.rowId
                );

                grid.emit(

                    'kanban.card.clicked',

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
     | Drag & Drop
     |===================================================== */

    function bindDrag(grid){

        if(
            !grid.__kanbanOptions
                ?.draggable
        ){

            return;
        }

        getCards(grid).forEach(card => {

            card.draggable = true;

            /*
            |--------------------------------------------------------------------------
            | Drag start
            |--------------------------------------------------------------------------
            */

            card.addEventListener(

                'dragstart',

                event => {

                    event.dataTransfer.setData(

                        'text/plain',

                        card.dataset.rowId
                    );

                    card.classList.add(
                        'dragging'
                    );

                    grid.emit(

                        'kanban.drag.start',

                        {

                            row:
                                card.dataset.rowId
                        }
                    );
                }
            );

            /*
            |--------------------------------------------------------------------------
            | Drag end
            |--------------------------------------------------------------------------
            */

            card.addEventListener(

                'dragend',

                () => {

                    card.classList.remove(
                        'dragging'
                    );

                    grid.emit(
                        'kanban.drag.end'
                    );
                }
            );
        });

        /*
        |--------------------------------------------------------------------------
        | Lanes
        |--------------------------------------------------------------------------
        */

        getLanes(grid).forEach(lane => {

            lane.addEventListener(

                'dragover',

                event => {

                    event.preventDefault();

                    lane.classList.add(
                        'dragover'
                    );
                }
            );

            lane.addEventListener(

                'dragleave',

                () => {

                    lane.classList.remove(
                        'dragover'
                    );
                }
            );

            lane.addEventListener(

                'drop',

                async event => {

                    event.preventDefault();

                    lane.classList.remove(
                        'dragover'
                    );

                    const row =
                        event.dataTransfer.getData(
                            'text/plain'
                        );

                    const laneId =
                        lane.dataset.laneId;

                    /*
                    |--------------------------------------------------------------------------
                    | Optimistic move
                    |--------------------------------------------------------------------------
                    */

                    const card =
                        grid.element?.querySelector(

                            `.kanban-card[data-row-id="${row}"]`
                        );

                    if(card){

                        lane
                            .querySelector(
                                '.kanban-lane-body'
                            )
                            ?.appendChild(card);
                    }

                    /*
                    |--------------------------------------------------------------------------
                    | Persist
                    |--------------------------------------------------------------------------
                    */

                    try {

                        await actions.execute(

                            grid,

                            'kanban.move',

                            {

                                row,

                                lane: laneId
                            }
                        );

                        grid.emit(

                            'kanban.card.moved',

                            {

                                row,

                                lane: laneId
                            }
                        );

                    } catch(err){

                        console.error(

                            '[kanban] move failed',

                            err
                        );

                        grid.emit(

                            'kanban.move.error',

                            {

                                row,

                                lane: laneId,

                                error: err
                            }
                        );
                    }
                }
            );
        });
    }

    /* =====================================================
     | Lane Collapse
     |===================================================== */

    function bindCollapse(grid){

        if(
            !grid.__kanbanOptions
                ?.collapsible
        ){

            return;
        }

        grid.element?.addEventListener(

            'click',

            event => {

                const toggle =
                    event.target.closest(
                        '[data-kanban-collapse]'
                    );

                if(!toggle){

                    return;
                }

                const lane =
                    toggle.closest(
                        '.kanban-lane'
                    );

                if(!lane){

                    return;
                }

                lane.classList.toggle(
                    'collapsed'
                );

                grid.emit(

                    'kanban.lane.collapsed',

                    {

                        lane:
                            lane.dataset.laneId,

                        collapsed:
                            lane.classList.contains(
                                'collapsed'
                            )
                    }
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

        grid.__kanbanOptions = {

            ...DEFAULTS,

            ...options
        };

        bindCards(grid);

        bindDrag(grid);

        bindCollapse(grid);

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

                bindCards(grid);

                bindDrag(grid);

                bindCollapse(grid);

                syncSelection(grid);
            }
        );

        /*
        |--------------------------------------------------------------------------
        | Mounted
        |--------------------------------------------------------------------------
        */

        grid.emit(
            'kanban.mounted'
        );
    }

    async function unmount(grid){

        grid.emit(
            'kanban.unmounted'
        );
    }

    return {

        compatible:[
            'kanban'
        ],

        mount,

        unmount
    };

});