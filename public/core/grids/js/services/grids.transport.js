__BORA_REGISTER_SERVICE__('grids.transport', async function(scope){

    const callbora =
        await scope.getService('callbora');

    /* =====================================================
     | Helpers
     |===================================================== */

    function buildPayload(grid, extra = {}){

        return {

            grid: grid.id,

            state: grid.getState(),

            renderer: grid.state.renderer,

            ...extra
        };
    }

    function normalizeResponse(response){

        if(typeof response === 'string'){

            try {

                response = JSON.parse(response);

            } catch(err){

                return {

                    success: false,

                    message: 'Invalid JSON response'
                };
            }
        }

        return response;
    }

    /* =====================================================
     | DOM
     |===================================================== */

    function replace(grid, html){

        if(!grid.element){

            return;
        }

        const wrapper =
            document.createElement('div');

        wrapper.innerHTML = html;

        const next =
            wrapper.firstElementChild;

        if(!next){

            return;
        }

        grid.element.replaceWith(next);

        grid.element = next;

        grid.emit('dom.replaced', {

            element: next
        });
    }

    function patchRow(grid, id, html){

        const row =
            grid.element?.querySelector(
                `[data-row-id="${id}"]`
            );

        if(!row){

            return;
        }

        const wrapper =
            document.createElement('tbody');

        wrapper.innerHTML = html;

        const next =
            wrapper.firstElementChild;

        if(next){

            row.replaceWith(next);
        }
    }

    function patchCell(grid, id, column, html){

        const cell =
            grid.element?.querySelector(
                `[data-row-id="${id}"] [data-column="${column}"]`
            );

        if(cell){

            cell.innerHTML = html;
        }
    }

    /* =====================================================
     | Requests
     |===================================================== */

    async function load(grid, extra = {}){

        grid.emit('transport.loading', {

            grid
        });

        const response =
            await callbora.post(

                'api/modules/grids/load',

                buildPayload(grid, extra)
            );

        const normalized =
            normalizeResponse(response);

        if(normalized.success){

            if(normalized.html){

                replace(grid, normalized.html);
            }

            if(normalized.state){

                grid.setState(
                    normalized.state
                );
            }

            grid.emit('transport.loaded', {

                response: normalized
            });

        } else {

            grid.emit('transport.error', {

                response: normalized
            });
        }

        return normalized;
    }

    async function reload(grid){

        return load(grid);
    }

    async function page(grid, page){

        grid.setState({

            page
        });

        return load(grid);
    }

    async function search(grid, query){

        grid.setState({

            search: query,

            page: 1
        });

        return load(grid);
    }

    async function filter(grid, filters = {}){

        grid.setState({

            filters,

            page: 1
        });

        return load(grid);
    }

    async function render(grid, renderer){

        await grid.setRenderer(renderer);

        return load(grid);
    }

    async function refreshRow(grid, id){

        const response =
            await callbora.post(

                'api/modules/grids/row',

                buildPayload(grid, {

                    row: id
                })
            );

        const normalized =
            normalizeResponse(response);

        if(normalized.success && normalized.html){

            patchRow(
                grid,
                id,
                normalized.html
            );
        }

        return normalized;
    }

    async function refreshCell(
        grid,
        id,
        column
    ){

        const response =
            await callbora.post(

                'api/modules/grids/cell',

                buildPayload(grid, {

                    row: id,

                    column
                })
            );

        const normalized =
            normalizeResponse(response);

        if(normalized.success && normalized.html){

            patchCell(
                grid,
                id,
                column,
                normalized.html
            );
        }

        return normalized;
    }

    return {

        load,

        reload,

        page,

        search,

        filter,

        render,

        replace,

        patchRow,

        patchCell,

        refreshRow,

        refreshCell
    };

});