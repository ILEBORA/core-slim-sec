__BORA_REGISTER_SERVICE__('grids.state', async function(scope){

    /* =====================================================
     | Defaults
     |===================================================== */

    const DEFAULT_STATE = {

        page: 1,

        limit: 25,

        renderer: 'table',

        search: '',

        sort: {

            column: null,

            direction: 'asc'
        },

        filters: {},

        columns: [],

        selected: [],

        snapshot: null,

        meta: {}
    };

    /* =====================================================
     | Helpers
     |===================================================== */

    function clone(value){

        return JSON.parse(
            JSON.stringify(value)
        );
    }

    function normalize(state = {}){

        return {

            ...clone(DEFAULT_STATE),

            ...clone(state),

            sort: {

                ...DEFAULT_STATE.sort,

                ...(state.sort || {})
            },

            filters: {

                ...(state.filters || {})
            },

            meta: {

                ...(state.meta || {})
            }
        };
    }

    function emit(grid){

        grid.emit(
            'state.changed',
            grid.state
        );
    }

    /* =====================================================
     | Core
     |===================================================== */

    function create(initial = {}){

        return normalize(initial);
    }

    function get(grid){

        return normalize(grid.state);
    }

    function set(grid, values = {}){

        grid.state = normalize({

            ...grid.state,

            ...values
        });

        emit(grid);

        return grid.state;
    }

    function reset(grid){

        grid.state = create();

        emit(grid);

        return grid.state;
    }

    function merge(grid, values = {}){

        return set(grid, values);
    }

    /* =====================================================
     | Pagination
     |===================================================== */

    function setPage(grid, page = 1){

        return set(grid, {

            page: parseInt(page, 10) || 1
        });
    }

    function setLimit(grid, limit = 25){

        return set(grid, {

            limit: parseInt(limit, 10) || 25
        });
    }

    /* =====================================================
     | Search
     |===================================================== */

    function setSearch(grid, query = ''){

        return set(grid, {

            search: query,

            page: 1
        });
    }

    function clearSearch(grid){

        return setSearch(grid, '');
    }

    /* =====================================================
     | Filters
     |===================================================== */

    function setFilters(grid, filters = {}){

        return set(grid, {

            filters,

            page: 1
        });
    }

    function updateFilter(
        grid,
        key,
        value
    ){

        const filters = {

            ...grid.state.filters,

            [key]: value
        };

        return setFilters(
            grid,
            filters
        );
    }

    function removeFilter(
        grid,
        key
    ){

        const filters = {

            ...grid.state.filters
        };

        delete filters[key];

        return setFilters(
            grid,
            filters
        );
    }

    function clearFilters(grid){

        return setFilters(grid, {});
    }

    /* =====================================================
     | Sorting
     |===================================================== */

    function setSort(
        grid,
        column,
        direction = 'asc'
    ){

        return set(grid, {

            sort: {

                column,

                direction
            }
        });
    }

    /* =====================================================
     | Renderer
     |===================================================== */

    function setRenderer(
        grid,
        renderer
    ){

        return set(grid, {

            renderer
        });
    }

    /* =====================================================
     | Selection
     |===================================================== */

    function select(
        grid,
        id
    ){

        const selected =
            new Set(grid.state.selected);

        selected.add(id);

        return set(grid, {

            selected: [
                ...selected
            ]
        });
    }

    function unselect(
        grid,
        id
    ){

        const selected =
            new Set(grid.state.selected);

        selected.delete(id);

        return set(grid, {

            selected: [
                ...selected
            ]
        });
    }

    function toggleSelection(
        grid,
        id
    ){

        const selected =
            new Set(grid.state.selected);

        if(selected.has(id)){

            selected.delete(id);

        } else {

            selected.add(id);
        }

        return set(grid, {

            selected: [
                ...selected
            ]
        });
    }

    function clearSelection(grid){

        return set(grid, {

            selected: []
        });
    }

    /* =====================================================
     | Persistence
     |===================================================== */

    function serialize(grid){

        return JSON.stringify(
            normalize(grid.state)
        );
    }

    function hydrate(
        grid,
        serialized
    ){

        try {

            const parsed =
                JSON.parse(serialized);

            return set(
                grid,
                parsed
            );

        } catch(err){

            console.error(
                '[grids.state] hydrate failed',
                err
            );
        }
    }

    function persist(
        grid,
        key = null
    ){

        key ||= `grid:${grid.id}`;

        localStorage.setItem(

            key,

            serialize(grid)
        );
    }

    function restore(
        grid,
        key = null
    ){

        key ||= `grid:${grid.id}`;

        const stored =
            localStorage.getItem(key);

        if(!stored){

            return null;
        }

        return hydrate(
            grid,
            stored
        );
    }

    return {

        DEFAULT_STATE,

        create,

        normalize,

        get,

        set,

        merge,

        reset,

        setPage,

        setLimit,

        setSearch,

        clearSearch,

        setFilters,

        updateFilter,

        removeFilter,

        clearFilters,

        setSort,

        setRenderer,

        select,

        unselect,

        toggleSelection,

        clearSelection,

        serialize,

        hydrate,

        persist,

        restore
    };

});