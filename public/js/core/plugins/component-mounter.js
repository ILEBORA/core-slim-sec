__BORA_REGISTER_PLUGIN__('ComponentMounter', function(scope){

    let mountedInstances = [];

    function init(){
        mountAll();
        scope.on('page.afterLoad', mountAll);
    }

    function mountAll(){
        mountedInstances.forEach(i => i.destroy?.());
        mountedInstances = [];

        document.querySelectorAll('[data-component]').forEach(el => {

            const name = el.dataset.component;
            const props = el.dataset.props
                ? JSON.parse(el.dataset.props)
                : {};

            const plugin = scope.getPlugin(name);

            if(plugin?.mount){
                const instance = plugin.mount(el, props);
                if(instance) mountedInstances.push(instance);
            }
        });
    }

    return { init };
});