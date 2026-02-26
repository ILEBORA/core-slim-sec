(function(global){

    const pendingPlugins = [];

    function registerDuringBuild(name, factory){
        pendingPlugins.push({name, factory});
    }

    function BoraRuntime(config){

        const services = new Map();
        const instances = new Map();
        const events = new Map();

        services.set('jquery', global.jQuery);

        function on(event, handler){
            if(!events.has(event)){
                events.set(event, []);
            }
            events.get(event).push(handler);
        }

        function emit(event, payload){
            if(!events.has(event)) return;
            events.get(event).forEach(fn => fn(payload));
        }

        function createScope(){
            return Object.freeze({
                services,
                on,
                emit
            });
        }

        function start(){
            if (window.__BORA_CORE_VERSIONS__) {
                console.log('Core versions:', window.__BORA_CORE_VERSIONS__);
            }
            
            pendingPlugins.forEach(function(p){
                const instance = p.factory(createScope());
                instances.set(p.name, instance);
                if(instance.init) instance.init();
            });
        }

        function plugin(name){
            return instances.get(name);
        }

        return {
            start,
            plugin
        };
    }

    global.BoraRuntime = BoraRuntime;
    global.__BORA_REGISTER_PLUGIN__ = registerDuringBuild;

})(window);