__BORA_REGISTER_PLUGIN__(
'inbox.plugin',

async function (scope) {

    // 🔧 Resolve services FIRST
    const callbora   = await scope.getService('callbora');
    const navigation = await scope.getService('navigation');
    const breadcrumbs = await scope.getService('breadcrumbs');

    // 🔧 Composition root (ONE place)
    const helpers = new InboxHelpers();

    const ui     = new InboxUI(scope, helpers);
    const typing = new InboxTyping(scope, callbora, ui);

    const presence      = new InboxPresence(ui);
    const notifications = new InboxNotifications(ui, navigation);

    const realtime = new InboxRealtime(
        scope,
        ui,
        typing,
        presence,
        notifications
    );

    const loader = new InboxThreadLoader(scope, callbora, ui, typing, realtime);

    const api = new InboxAPI({
        ui,
        realtime,
        loader,
        typing
    });

    // 🔒 Internal state
    const state = {
        mounted: false
    };

    // =========================
    // LIFECYCLE
    // =========================

    function mount() {
        if (state.mounted) return;

        state.mounted = true;

        ui.bind();

        breadcrumbs.set([
            { label: 'Inbox', href: 'portal/inbox' },
            // { label: 'Loading...', current: true }
        ]);

        scope.on('inbox.thread.open', (e) => {
            breadcrumbs.set([
                { label: 'Inbox', href: 'portal/inbox' },
                { label: '<img src="assets/images/icons/ajax.gif"/>', current: true }
            ]);
            api.openThread(e.threadId);
        });

        scope.on('inbox.message.sent', (e)=>{
            // ui.appendMessage(e);
        });

        const container = document.querySelector('.messages');

        if (!container) {
            requestAnimationFrame(mount); // ⚠️ fixed (no this)
            return;
        }

        // loader.resolveThreadFromRoute();

        scope.on('page.loaded', async (url) => {
            loader.resolveThreadFromRoute();
            realtime.initUserChannel();
        });

        $(async function(){
            await attachInteractions();
        });
    }

    function unmount() {
        if (!state.mounted) return; // ⚠️ FIXED (was wrong)
        state.mounted = false;

        ui.unbind();
        realtime.destroy();

        scope.off('page.loaded');
    }

    //
    async function attachInteractions(){
         //attach
        const uiInteractions = await scope.getPlugin('inbox.ui.interactions');
        uiInteractions.init();
    }

    // =========================
    // PUBLIC API
    // =========================

    return {
        mount,
        unmount,

        loadThread: api.loadThread.bind(api),
        openThread: api.openThread.bind(api),
        appendMessage: api.appendMessage.bind(api)
    };
},

{
    requires: ['callbora', 'permissions', 'navigation'],

    activateOn: (route) => route.startsWith('portal/inbox'),

    // faces: ['client', 'admin'], // or just ['admin'] if strict

    // permissions: (appcore) => {
    //     if(!appcore) return false;
    //     return appcore.hasPermission('Inbox', 'view') === true;
    // },

    // priority: 10,        // optional (UI plugin → medium priority)
    // dependsOn: [],       // optional (if later needed)
    // stage: 'immediate'   // default anyway
});