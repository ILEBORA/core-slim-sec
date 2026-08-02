__BORA_REGISTER_PLUGIN__(
'pages.plugin',

async function (scope) {

    // Resolve services FIRST
    // const callbora   = await scope.getService('callbora');
    const uiStack = await __BORA_APP__.service('ui.stack');
    const navigation = await scope.getService('navigation');
    const uiActions = await scope.getService('ui.actions');
    const pageActions = await scope.getPlugin('page.actions');


    // Internal state
    const state = {
        mounted: false
    };

    // =========================
    // LIFECYCLE
    // =========================

    function mount() {
        if (state.mounted) return;

        state.mounted = true;
        // alert('Mounted pages');

        $(function(){
            uiBind();
        })

        // realtime.initUserChannel();

        // scope.on('inbox.thread.open', (e) => {
        //     api.openThread(e.threadId);
        // });

        // const container = document.querySelector('.messages');

        // if (!container) {
        //     requestAnimationFrame(mount); // ⚠️ fixed (no this)
        //     return;
        // }

        // loader.resolveThreadFromRoute();

        // scope.on('page.loaded', () => {
        //     loader.resolveThreadFromRoute();
        // });
    }

    function unmount() {
        if (!state.mounted) return; // ⚠️ FIXED (was wrong)

        state.mounted = false;

        uiUnbind();
        realtime.destroy();
    }

    function uiBind(){
        uiActions.register('page.edit', async (el)=>{
            const pageId = el.dataset.id;
            alert(pageId);
            await pageActions.openPageEditor(pageId);
        });

        uiActions.register('page.dublicate', (el)=>{
            const pageId = el.dataset.id;
            pageActions.openDublicate(pageId);
        });

        uiActions.register('page.add-subpage', (el)=>{
            const pageId = el.dataset.id;
            pageActions.openSubpageModal(pageId);
        });

        uiActions.register('page.arrange', (el)=>{
            const pageId = el.dataset.id;
            pageActions.openArrangeUI(pageId);
        });



        uiActions.register('page.toggle-status', (el)=>{
            const pageId = el.dataset.id;
            pageActions.togglePageStatus(pageId);
        });


        uiActions.register('page.settings', (el)=>{
            const pageId = el.dataset.id;
            pageActions.openMotherPageSettings(pageId);
        });


        uiActions.register('page.delete', (el)=>{
            const pageId = el.dataset.id;
            pageActions.confirmDelete(pageId);
        });


        //Panel Actions
        uiActions.register('thread.open', (el)=>{
            const threadId = el.dataset.thread;
            uiStack.closeTop();
            navigation?.go(`portal/inbox/thread/${threadId}`);
        });

        scope.on('preferences:before-change', async ({ key, value, preventDefault }) => {

            if(key === 'language'){

                const alerts = await scope.getPlugin('alerts');

                alerts.confirm('Change language? The app will reload.', {
                        html: true
                }).autoCancel(20)
                .then(function() {
                    // Allow change, but override flow
                    setTimeout(async () => {
                        const prefs = await scope.getService('preferences');
                        await prefs.save();
                        location.reload();
                    }, 0);
                }, function() {
                    logTest('Confirmation canceled');
                });
                
                preventDefault();                
            }
        });

    }

    function uiUnbind(){

    }

    // =========================
    // PUBLIC API
    // =========================

    return {
        mount,
        unmount,

        // loadThread: api.loadThread.bind(api),
        // openThread: api.openThread.bind(api),
        // appendMessage: api.appendMessage.bind(api)
    };



},
{
    requires: ['callbora', 'permissions', 'navigation'],

    // activateOn: (route) => route.startsWith('portal/inbox'),

    // faces: ['client', 'admin'], // or just ['admin'] if strict

    // permissions: (appcore) => {
    //     if(!appcore) return false;
    //     return appcore.hasPermission('Pages', 'editpages') === true;
    // },

    // priority: 10,        // optional (UI plugin → medium priority)
    // dependsOn: [],       // optional (if later needed)
    // stage: 'immediate'   // default anyway
});



// mPGs.openPageEditor = function(id) {
//     // return mPGs.klassPopup('pages', 'manage', id, 'edit');
//     // return mPGs.klassPopup('pages', 'manage', id, 'edit', null, null, null);
//     const popup = window.__BORA_APP__?.plugin?.('popup');
//     if (!popup) return;

//     popup.open({
//         mode:   'form',
//         module: 'pages',
//         group:  'manage',
//         view:   'edit',
//         id:     id,
//         tab:    'edit',
//         size:   'md',
//         meta:   null
//     });
// };

// mPGs.openMotherPageSettings = function (id, tab = 'settings') {
//     // return mPGs.klassPopup('pages', 'manage', id, 'settings', null, null, null);
//     const popup = window.__BORA_APP__?.plugin?.('popup');
//     if (!popup) return;

//     popup.open({
//         mode:   'form',
//         module: 'pages',
//         group:  'manage',
//         view:   'settings',
//         id:     id,
//         tab:    'settings',
//         size:   'md',
//         meta:   null
//     });
// };


// mPGs.openSubpageModal = function(id){
//     // return mPGs.klassPopup('pages', 'manage', id, 'subpage', null, null, null);
//     const popup = window.__BORA_APP__?.plugin?.('popup');
//     if (!popup) return;

//     popup.open({
//         mode:   'form',
//         module: 'pages',
//         group:  'manage',
//         view:   'subpage',
//         id:     id,
//         tab:    'subpage',
//         size:   'md',
//         meta:   null
//     });
// };

// mPGs.openArrangeUI = function(id){
//     // return mPGs.klassPopup('pages', 'manage', null, 'arrange', null, null, null);
//     const popup = window.__BORA_APP__?.plugin?.('popup');
//     if (!popup) return;

//     popup.open({
//         mode:   'form',
//         module: 'pages',
//         group:  'manage',
//         view:   'arrange',
//         id:     id,
//         tab:    'arrange',
//         size:   'md',
//         meta:   null
//     });
// };

// mPGs.togglePageStatus = function(id){
//     // return mPGs.klassPopup('pages', 'manage', id, 'toggle', null, null, null);
//     const popup = window.__BORA_APP__?.plugin?.('popup');
//     if (!popup) return;

//     popup.open({
//         mode:   'form',
//         module: 'pages',
//         group:  'manage',
//         view:   'toggle',
//         id:     id,
//         tab:    'toggle',
//         size:   'md',
//         meta:   null
//     });
// };


// mPGs.confirmDelete = function(id){
//     alertBora.confirm('Are you <em>really</em> sure?', {
//             html: true
//     }).autoCancel(20)
//     .then(function() {
//         // TODO:: soft delete
//         alert('Delete not activated.');
//     }, function() {
//         logTest('Confirmation canceled');
//     });
// };


// $(function(){
//     alertBora.set('notifierPosition', 'bottom-left').set('notifierDelay', 4);
//     alertBora.notify('Pages Module active!', 'success', 5);
// });




