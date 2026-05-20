__BORA_REGISTER_SERVICE__('grids.selection', async function(scope){

    const state =
        await scope.getService(
            'grids.state'
        );

    /* =====================================================
     | Helpers
     |===================================================== */

    function getSet(grid){

        return new Set(
            grid.state.selected || []
        );
    }

    function update(grid, values){

        state.set(grid, {

            selected: [
                ...values
            ]
        });

        syncDOM(grid);

        grid.emit(

            'selection.changed',

            {

                selected: all(grid),

                count: count(grid)
            }
        );
    }

    /* =====================================================
     | Core
     |===================================================== */

    function select(
        grid,
        id
    ){

        const selected =
            getSet(grid);

        selected.add(id);

        update(
            grid,
            selected
        );
    }

    function unselect(
        grid,
        id
    ){

        const selected =
            getSet(grid);

        selected.delete(id);

        update(
            grid,
            selected
        );
    }

    function toggle(
        grid,
        id
    ){

        const selected =
            getSet(grid);

        if(selected.has(id)){

            selected.delete(id);

        } else {

            selected.add(id);
        }

        update(
            grid,
            selected
        );
    }

    function clear(grid){

        update(
            grid,
            new Set()
        );
    }

    function selectAll(
        grid,
        ids = []
    ){

        update(
            grid,
            new Set(ids)
        );
    }

    /* =====================================================
     | Range Selection
     |===================================================== */

    function range(
        grid,
        ids = [],
        start,
        end
    ){

        const selected =
            getSet(grid);

        const startIndex =
            ids.indexOf(start);

        const endIndex =
            ids.indexOf(end);

        if(
            startIndex === -1 ||
            endIndex === -1
        ){

            return;
        }

        const slice = ids.slice(

            Math.min(
                startIndex,
                endIndex
            ),

            Math.max(
                startIndex,
                endIndex
            ) + 1
        );

        slice.forEach(id => {

            selected.add(id);
        });

        update(
            grid,
            selected
        );
    }

    /* =====================================================
     | Info
     |===================================================== */

    function isSelected(
        grid,
        id
    ){

        return getSet(grid)
            .has(id);
    }

    function count(grid){

        return getSet(grid)
            .size;
    }

    function all(grid){

        return [
            ...getSet(grid)
        ];
    }

    /* =====================================================
     | DOM Sync
     |===================================================== */

    function syncDOM(grid){

        if(!grid.element){

            return;
        }

        /*
        |--------------------------------------------------------------------------
        | Rows
        |--------------------------------------------------------------------------
        */

        grid.element
            .querySelectorAll(
                '[data-row-id]'
            )
            .forEach(el => {

                const id =
                    el.dataset.rowId;

                el.classList.toggle(

                    'selected',

                    isSelected(
                        grid,
                        id
                    )
                );
            });

        /*
        |--------------------------------------------------------------------------
        | Checkboxes
        |--------------------------------------------------------------------------
        */

        grid.element
            .querySelectorAll(
                '[data-grid-select]'
            )
            .forEach(el => {

                const id =
                    el.dataset.gridSelect;

                el.checked =
                    isSelected(
                        grid,
                        id
                    );
            });

        /*
        |--------------------------------------------------------------------------
        | Bulk state
        |--------------------------------------------------------------------------
        */

        grid.element
            .dataset.selectionCount =
                count(grid);
    }

    /* =====================================================
     | Persistence
     |===================================================== */

    function persist(grid){

        localStorage.setItem(

            `grid-selection:${grid.id}`,

            JSON.stringify(
                all(grid)
            )
        );
    }

    function restore(grid){

        const stored =
            localStorage.getItem(

                `grid-selection:${grid.id}`
            );

        if(!stored){

            return;
        }

        try {

            const parsed =
                JSON.parse(stored);

            selectAll(
                grid,
                parsed
            );

        } catch(err){

            console.error(
                '[grids.selection] restore failed',
                err
            );
        }
    }

    return {

        select,

        unselect,

        toggle,

        clear,

        selectAll,

        range,

        isSelected,

        count,

        all,

        syncDOM,

        persist,

        restore
    };

});