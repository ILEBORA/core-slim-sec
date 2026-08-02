__BORA_REGISTER_PLUGIN__('dashboards.actions', async function(scope){

    const callbora = await scope.getService('callbora');
    const feedUI  = await scope.getPlugin('dashboards.feed.ui');
    const dashboardsComposer  = await scope.getPlugin('dashboards.composer');
    const uiStack = await __BORA_APP__.service('ui.stack');
    const uiActions = await scope.getService('ui.actions');
    const popup = await scope.getPlugin('popup');
    const routeRegistry = await scope.getService('route.registry');

    const dismissable = await __BORA_APP__.service('ui.dismissable');
    const bNavigator = await scope.getService('navigator');

    const state = {
        mounted: false,
        initialized:false
    };

    function mount(){
        if (state.mounted) return;
        state.mounted = true;
    }

    function unmount(){
        if (!state.mounted) return;
        state.mounted = false;
    }


    function init(){
        if (state.initialized) return;
        state.initialized = true;

        console.log('[dashboards.actions] mounted');

        //popups
        uiActions.register('dashboard.toggle-controls',()=>{
            console.log('toggle controls');
        });

    }

    return { mount, unmount };

},{
    // activateOn: (route) => route.startsWith('portal/dashboards')
});