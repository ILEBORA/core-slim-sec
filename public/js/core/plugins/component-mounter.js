__BORA_REGISTER_PLUGIN__('component.mounter', function(scope){

    let mountedInstances = [];

    const state = {
        mounted: false
    };

    function mount(){
        if (state.mounted) return;
        state.mounted = true;

        console.log('[component.mounter] mounted');
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

    function unmount(){
        if (!state.mounted) return;
        state.mounted = false;  

    }

    return { mount };
});