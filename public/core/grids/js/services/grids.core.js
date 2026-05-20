__BORA_REGISTER_SERVICE__('grids.core', async function(scope){

    const registry = new Map();

    class GridInstance {

        constructor(config = {}){

            this.id = config.id || crypto.randomUUID();

            this.config = config;

            this.element = null;

            this.plugins = new Map();

            this.events = new Map();

            this.state = {

                page: 1,

                renderer: config.renderer || 'table',

                filters: {},

                search: '',

                selected: []
            };
        }

        /* -----------------------------------------
         * Lifecycle
         * ----------------------------------------- */

        async mount(target = null){

            if(target){

                this.element =
                    typeof target === 'string'
                        ? document.querySelector(target)
                        : target;
            }

            this.emit('mount', this);

            return this;
        }

        async destroy(){

            this.emit('destroy', this);

            this.plugins.clear();

            this.events.clear();

            registry.delete(this.id);
        }

        /* -----------------------------------------
         * Plugins
         * ----------------------------------------- */

        async use(pluginName, options = {}){

            if(this.plugins.has(pluginName)){

                return this.plugins.get(pluginName);
            }

            const plugin =
                await scope.getPlugin(pluginName);

            if(plugin?.mount){

                await plugin.mount(this, options);
            }

            this.plugins.set(pluginName, plugin);

            this.emit('plugin.loaded', {

                plugin: pluginName
            });

            return plugin;
        }

        /* -----------------------------------------
         * Events
         * ----------------------------------------- */

        on(event, callback){

            if(!this.events.has(event)){

                this.events.set(event, []);
            }

            this.events
                .get(event)
                .push(callback);

            return this;
        }

        emit(event, payload = {}){

            const listeners =
                this.events.get(event) || [];

            listeners.forEach(fn => {

                try {

                    fn(payload);

                } catch(err){

                    console.error(
                        `[Grid:${this.id}] Event error`,
                        err
                    );
                }
            });

            return this;
        }

        /* -----------------------------------------
         * State
         * ----------------------------------------- */

        setState(values = {}){

            this.state = {

                ...this.state,

                ...values
            };

            this.emit('state.changed', this.state);

            return this;
        }

        getState(){

            return this.state;
        }

        /* -----------------------------------------
         * Renderer
         * ----------------------------------------- */

        async setRenderer(renderer){

            this.state.renderer = renderer;

            this.emit('renderer.changed', {

                renderer
            });

            return this;
        }
    }

    /* =====================================================
     | Service API
     |===================================================== */

    async function create(config = {}){

        const grid =
            new GridInstance(config);

        registry.set(grid.id, grid);

        return grid;
    }

    function get(id){

        return registry.get(id);
    }

    function destroy(id){

        const grid = registry.get(id);

        if(grid){

            grid.destroy();
        }
    }

    function all(){

        return Array.from(
            registry.values()
        );
    }

    async function scan(selector = '.grid-wrapper'){

        const grids =
            document.querySelectorAll(selector);

        for(const el of grids){

            const id =
                el.dataset.gridId
                || crypto.randomUUID();

            if(registry.has(id)){

                continue;
            }

            const grid = await create({

                id,

                renderer:
                    el.dataset.gridType
                    || 'table'
            });

            await grid.mount(el);

            el.__gridInstance = grid;
        }
    }

    return {

        create,

        get,

        destroy,

        all,

        scan
    };

});