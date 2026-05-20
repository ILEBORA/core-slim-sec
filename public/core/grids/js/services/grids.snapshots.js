__BORA_REGISTER_SERVICE__('grids.snapshots', async function(scope){

    const callbora =
        await scope.getService(
            'callbora'
        );

    const state =
        await scope.getService(
            'grids.state'
        );

    const renderers =
        await scope.getService(
            'grids.renderers'
        );

    /* =====================================================
     | Helpers
     |===================================================== */

    function normalize(snapshot = {}){

        return {

            id:
                snapshot.id
                || crypto.randomUUID(),

            name:
                snapshot.name
                || 'Untitled Snapshot',

            renderer:
                snapshot.renderer
                || 'table',

            state:
                snapshot.state
                || {},

            meta: {

                scope: 'user',

                created_at:
                    new Date().toISOString(),

                updated_at:
                    new Date().toISOString(),

                ...(snapshot.meta || {})
            }
        };
    }

    /* =====================================================
     | Snapshot Creation
     |===================================================== */

    function create(
        grid,
        options = {}
    ){

        return normalize({

            name:
                options.name
                || grid.id,

            renderer:
                grid.state.renderer,

            state:
                state.get(grid),

            meta:
                options.meta || {}
        });
    }

    /* =====================================================
     | Local Persistence
     |===================================================== */

    function persistLocal(
        grid,
        snapshot
    ){

        localStorage.setItem(

            `grid-snapshot:${grid.id}`,

            JSON.stringify(snapshot)
        );

        grid.emit(

            'snapshot.saved.local',

            snapshot
        );

        return snapshot;
    }

    function restoreLocal(grid){

        const stored =
            localStorage.getItem(

                `grid-snapshot:${grid.id}`
            );

        if(!stored){

            return null;
        }

        try {

            const parsed =
                JSON.parse(stored);

            return restore(
                grid,
                parsed
            );

        } catch(err){

            console.error(
                '[grids.snapshots] restoreLocal failed',
                err
            );
        }
    }

    /* =====================================================
     | Server Persistence
     |===================================================== */

    async function save(
        grid,
        snapshot
    ){

        snapshot =
            normalize(snapshot);

        const response =
            await callbora.post(

                'api/modules/grids/snapshot/save',

                {

                    grid: grid.id,

                    snapshot
                }
            );

        grid.emit(

            'snapshot.saved',

            {

                snapshot,

                response
            }
        );

        return response;
    }

    async function load(
        grid,
        snapshotId
    ){

        const response =
            await callbora.post(

                'api/modules/grids/snapshot/load',

                {

                    grid: grid.id,

                    snapshot: snapshotId
                }
            );

        if(
            response.success &&
            response.snapshot
        ){

            return normalize(
                response.snapshot
            );
        }

        return null;
    }

    async function remove(
        grid,
        snapshotId
    ){

        return await callbora.post(

            'api/modules/grids/snapshot/delete',

            {

                grid: grid.id,

                snapshot: snapshotId
            }
        );
    }

    async function all(grid){

        return await callbora.post(

            'api/modules/grids/snapshot/all',

            {

                grid: grid.id
            }
        );
    }

    /* =====================================================
     | Restore
     |===================================================== */

    async function restore(
        grid,
        snapshot
    ){

        snapshot =
            normalize(snapshot);

        /*
        |--------------------------------------------------------------------------
        | State
        |--------------------------------------------------------------------------
        */

        state.set(

            grid,

            snapshot.state
        );

        /*
        |--------------------------------------------------------------------------
        | Renderer
        |--------------------------------------------------------------------------
        */

        await renderers.switch(

            grid,

            snapshot.renderer,

            false
        );

        /*
        |--------------------------------------------------------------------------
        | Events
        |--------------------------------------------------------------------------
        */

        grid.emit(

            'snapshot.restored',

            {

                snapshot
            }
        );

        return snapshot;
    }

    async function activate(
        grid,
        snapshotId
    ){

        const snapshot =
            await load(

                grid,

                snapshotId
            );

        if(!snapshot){

            return null;
        }

        return restore(
            grid,
            snapshot
        );
    }

    /* =====================================================
     | Import / Export
     |===================================================== */

    function exportSnapshot(snapshot){

        return JSON.stringify(

            normalize(snapshot),

            null,

            2
        );
    }

    function importSnapshot(json){

        try {

            return normalize(

                JSON.parse(json)
            );

        } catch(err){

            console.error(
                '[grids.snapshots] import failed',
                err
            );

            return null;
        }
    }

    /* =====================================================
     | Autosave
     |===================================================== */

    function autosave(
        grid,
        delay = 1000
    ){

        let timer = null;

        grid.on(

            'state.changed',

            () => {

                clearTimeout(timer);

                timer = setTimeout(() => {

                    const snapshot =
                        create(grid);

                    persistLocal(
                        grid,
                        snapshot
                    );

                }, delay);
            }
        );
    }

    return {

        create,

        save,

        load,

        restore,

        activate,

        remove,

        all,

        persistLocal,

        restoreLocal,

        export: exportSnapshot,

        import: importSnapshot,

        autosave
    };

});