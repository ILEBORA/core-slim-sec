__BORA_REGISTER_PLUGIN__(
'people.plugin',

async function (scope) {

    // 🔧 Core services
    const callbora          = await scope.getService('callbora');
    const navigation        = await scope.getService('navigation');
    const uiInteractions    = await scope.getPlugin('people.ui.interactions');
    const breadcrumbs       = await scope.getService('breadcrumbs');

    // 🔧 Composition root (SIMPLIFIED)
    const ui     = new PeopleUI(scope);
    const loader = new PeopleLoader(scope, callbora);

    const follow = new PeopleFollow(callbora, ui, loader);

    const presence      = new PeoplePresence(ui);
    const notifications = new PeopleNotifications(ui, navigation);

    const tabs = new PeopleTabs(scope);

    const realtime = new PeopleRealtime(
        scope,
        ui,
        presence,
        notifications,
        follow,
        loader
    );

    const api = new PeopleAPI({
        ui,
        loader,
        follow,
        realtime
    });

    const state = {
        mounted: false
    };

    /* ========================================
     * MOUNT
     * ====================================== */

    function mount() {
        if (state.mounted) return;
        state.mounted = true;

        ui.bind();
        realtime.initUserChannel();

        bindEvents();
        attachInteractions();

        // route handling
        scope.on('page.loaded', () => {
            loader.resolvePersonFromRoute();
        });
    }

    /* ========================================
     * EVENTS
     * ====================================== */

    function bindEvents() {

        // OPEN PERSON (🔥 now uses API)
        scope.on('people.person.open', async ({ personId }) => {
            // optimistic breadcrumb (instant feedback)
            breadcrumbs.set([
                { label: 'People', href: 'portal/people' },
                { label: 'Loading...', current: true }
            ]);
            
            await api.openProfile(personId);
        });

        // TABS
        scope.on('people.tab.changed', async ({ tab, personId }) => {

            const root = document.querySelector(
                `.person-view[data-person="${personId}"]`
            );

            if (root) {
                root.querySelectorAll('.person-tabs button')
                    .forEach(btn => {
                        btn.classList.toggle(
                            'active',
                            btn.dataset.tab === tab
                        );
                    });

                root.querySelectorAll('.tab-panel')
                    .forEach(panel => {
                        panel.classList.toggle(
                            'active',
                            panel.dataset.tab === tab
                        );
                    });
            }

            await api.loadTab(personId, tab);
        });
        // scope.on('people.tab.changedO', async ({ tab, personId }) => {
        //      const root = document.querySelector(
        //         `.person-view[data-person="${personId}"]`
        //     );

        //     if (!root) return;

        //     // ✅ update UI FIRST (instant feedback)
        //     tabs.activate(root, tab);

        //     // ✅ then load data (async)
        //     await api.loadTab(personId, tab);
        // });

        scope.on('people.tab.ui', ({ tab, personId, root }) => {
            tabs.setTab(root, personId, tab);
        });

        // TAB PRELOAD (🔥 new)
        scope.on('people.tab.preload', ({ tab, personId }) => {
            loader.preloadTab(personId, tab);
        });

        // PERSON PRELOAD (🔥 new)
        scope.on('people.person.preload', ({ personId }) => {
            loader.loadPersonView(personId).catch(() => {});
        });

        // FOLLOW
        scope.on('people.follow.toggle', async ({ personId, isFollowing }) => {
            await api.toggleFollow(personId, isFollowing);
        });

        // BACK
        scope.on('people.back', () => {
            ui.clearDetail();
        });

        scope.on('people.tree.selected', async ({ personId, treeId }) => {

            const graph = await api.loadTree(personId, treeId);

            // ui.renderTree(graph);

        });
    }

    /* ========================================
     * UNMOUNT
     * ====================================== */

    function unmount() {
        if (!state.mounted) return;

        state.mounted = false;

        ui.unbind();
        realtime.destroy();

        scope.off('page.loaded');
        scope.off('people.person.open');
    }

    /* ========================================
     * INTERACTIONS
     * ====================================== */

    function attachInteractions() {
        uiInteractions.init();
    }

    /* ========================================
     * PUBLIC API
     * ====================================== */

    return {
        mount,
        unmount,

        openProfile: api.openProfile.bind(api),
        follow: api.follow.bind(api)
    };

},

{
    requires: ['callbora', 'permissions', 'navigation'],

    activateOn: (route) => (
        route === 'portal/people' ||
        route.startsWith('portal/people/')// ||

        
    )
});