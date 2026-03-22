__BORA_REGISTER_PLUGIN__('ComponentMounter', function(scope){

    let mountedInstances = [];

    function mount(){
        console.log('[ComponentMounter] mounted');
        mountAll();
        scope.on('page.afterLoad', mountAll);
    }

    function mountAll(){
        mountedInstances.forEach(i => i.destroy?.());
        mountedInstances = [];

        document.querySelectorAll('[data-component]').forEach(async el => {

            const name = el.dataset.component;
            const props = el.dataset.props
                ? JSON.parse(el.dataset.props)
                : {};

            const plugin = await scope.getPlugin(name);

            if(plugin?.mount){
                const instance = plugin.mount(el, props);
                if(instance) mountedInstances.push(instance);
            }
        });
    }

    return { mount };
});