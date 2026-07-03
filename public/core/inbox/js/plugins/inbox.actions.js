__BORA_REGISTER_PLUGIN__('inbox.actions', async function(scope){

    const callbora = await scope.getService('callbora');
    // const feedUI  = await scope.getPlugin('activity.workspace');
    const activityComposer  = await scope.getPlugin('activity.composer');
    const uiStack = await __BORA_APP__.service('uiStack');
    const uiActions = await scope.getService('ui.actions');
    const navigation = await scope.getService('navigation');
    const popup = await scope.getPlugin('popup');
    // const routeRegistry = await scope.getService('route.registry');

    const dismissable = await __BORA_APP__.service('ui.dismissable');
    const bNavigator = await scope.getService('navigator');

    // 🔧 Composition root (ONE place)
    // const helpers = new InboxHelpers();

    // const ui     = new InboxUI(scope, helpers);
    // const typing = new InboxTyping(scope, callbora, ui);

    // const presence      = new InboxPresence(ui);
    // const notifications = new InboxNotifications(ui, navigation);

    // const realtime = new InboxRealtime(
    //     scope,
    //     ui,
    //     typing,
    //     presence,
    //     notifications
    // );

    // const loader = new InboxThreadLoader(scope, callbora, ui, typing, realtime);

    // const api = new InboxAPI({
    //     ui,
    //     realtime,
    //     loader,
    //     typing
    // });

    const state = {
        mounted: false,
        initialized:false
    };

    function mount(){
        if (state.mounted) return;
        state.mounted = true;

        // init();

        realtime.initUserChannel();        
    }

    function unmount(){
        if (!state.mounted) return;
        state.mounted = false;
    }

    function init(){
        if(state.initialized) return;
        state.initialized = true;
        
        // alert('Inbox Actions');
    }

    init();

    return {
        mount,
        unmount,
        init
    }

});