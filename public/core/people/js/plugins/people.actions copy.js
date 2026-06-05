__BORA_REGISTER_PLUGIN__('people.actions', async function(scope){

    const callbora = await scope.getService('callbora');
    const feedUI  = await scope.getPlugin('activity.feed.ui');
    const activityComposer  = await scope.getPlugin('activity.composer');
    const uiStack = await __BORA_APP__.service('uiStack');
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
        if(state.initialized) return;
        state.initialized = true;
        
        alert('People Actions');

        
    }

    init();

    return {
        mount,
        unmount,
        init
    }

});