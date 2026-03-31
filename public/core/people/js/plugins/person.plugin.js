__BORA_REGISTER_PLUGIN__(
'people.plugin',

async function (scope) {

    // 🔧 Resolve core services
    const callbora   = await scope.getService('callbora');
    const navigation = await scope.getService('navigation');

    // 🔧 Composition root
    const helpers = new PeopleHelpers();

    const ui     = new PeopleUI(scope, helpers);
    const loader = new PeopleLoader(scope, callbora, ui);

    const tree   = new PeopleTree(loader);
    const follow = new PeopleFollow(callbora, ui);

    const presence      = new PeoplePresence(ui);
    const notifications = new PeopleNotifications(ui, navigation);

    const realtime = new PeopleRealtime(
        scope,
        ui,
        presence,
        notifications,
        follow
    );

    const api = new PeopleAPI({
        ui,
        loader,
        tree,
        follow,
        realtime
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

        realtime.initUserChannel();

        // ---------------------
        // ROUTE HANDLING
        // ---------------------

        scope.on('page.loaded', () => {
            loader.resolvePersonFromRoute();
        });

        // ---------------------
        // EVENTS
        // ---------------------

        scope.on('people.profile.open', (e) => {
            api.openProfile(e.personId);
        });

        // ---------------------
        // DOM READY
        // ---------------------

        const container = document.querySelector('.people-container');

        if (!container) {
            requestAnimationFrame(mount);
            return;
        }

        $(async function () {
            await attachInteractions();
        });
    }

    function unmount() {
        if (!state.mounted) return;

        state.mounted = false;

        ui.unbind();
        realtime.destroy();

        scope.off('page.loaded');
        scope.off('people.profile.open');
    }

    async function attachInteractions() {
        const uiInteractions = await scope.getPlugin('people.ui.interactions');
        uiInteractions.init();
    }

    // =========================
    // PUBLIC API
    // =========================

    return {
        mount,
        unmount,

        openProfile: api.openProfile.bind(api),
        loadPerson: api.loadPerson.bind(api),
        follow: api.follow.bind(api)
    };

},

{
    requires: ['callbora', 'permissions', 'navigation'],

    activateOn: (route) => route.startsWith('portal/people'),

    // permissions: (appcore) => {
    //     return appcore.hasPermission('People', 'view');
    // },
});