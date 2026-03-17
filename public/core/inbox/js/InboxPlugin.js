__BORA_REGISTER_PLUGIN__(
'Inbox',
function(scope){

    const callbora = scope.getService('callbora');
    const navigation = scope.getService('navigation');

    const helpers = new InboxHelpers();

    const ui       = new InboxUI(scope, helpers);
    const typing   = new InboxTyping(scope, callbora, ui);

    const loader   = new InboxThreadLoader(scope, callbora, ui, typing);

    const presence      = new InboxPresence(ui);
    const notifications = new InboxNotifications(ui, navigation);

    const realtime = new InboxRealtime(
        scope, 
        ui, 
        typing,
        presence,
        notifications
    );

    
    const state = {
        mounted:false,
        // threadId:null,
        // threadHook:null,
        // mainUserId: rd('uID') ?? window.MAIN_USER_ID ?? null,
        loadingHistory:false
    };
    
    

    const api = new InboxAPI({
        ui,
        realtime,
        loader,
        typing
    });

    function mount(){
        if(state.mounted) return;
        
        state.mounted = true;

        ui.bind();
        realtime.initUserChannel();

        scope.on('inbox.thread.open', e=>{
             api.openThread(e.threadId);
        });

        const container = document.querySelector('.messages');

        if(!container){
            requestAnimationFrame(()=>this.mount());
            return;
        }

        loader.resolveThreadFromRoute();
    }

    function unmount(){
        if(state.mounted) return;

        state.mounted = true;

        ui.unbind();
        realtime.destroy();
    }

    return {
        mount,
        unmount,

        // public entry points
        loadThread: api.loadThread.bind(api),
        openThread: api.openThread.bind(api),
        appendMessage: api.appendMessage.bind(api)
    };

},
{
    requires:['callbora','permissions','face','navigation'],
    activateOn:(route)=>route.startsWith('portal/inbox')
});