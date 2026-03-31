class PeopleTabs {

    constructor(scope, ui) {
        this.scope = scope;
        this.ui    = ui;

        this.state = {
            activeTab: 'profile'
        };

        this.cache = {
            root: null
        };
    }

    /**
     * Bind to current person view
     */
    bind(root) {
        if (!root) return;

        this.cache.root = root;

        this.attachEvents();
        this.activate(this.state.activeTab);
    }

    unbind() {
        this.cache.root = null;
    }

    /**
     * Attach DOM listeners
     */
    attachEvents() {
        const root = this.cache.root;
        if (!root) return;

        root.querySelectorAll('.person-tabs button')
            .forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const tab = btn.dataset.tab;
                    this.setTab(tab);
                });
            });
    }

    /**
     * Public setter
     */
    setTab(tab) {
        if (!tab || tab === this.state.activeTab) return;

        this.state.activeTab = tab;

        this.activate(tab);

        // emit event for other modules (tree, activity, etc.)
        this.scope.emit('people.tab.changed', {
            tab
        });
    }

    /**
     * Apply UI changes
     */
    activate(tab) {
        const root = this.cache.root;
        if (!root) return;

        // tabs
        root.querySelectorAll('.person-tabs button')
            .forEach(btn => {
                btn.classList.toggle(
                    'active',
                    btn.dataset.tab === tab
                );
            });

        // panels
        root.querySelectorAll('.tab-panel')
            .forEach(panel => {
                panel.classList.toggle(
                    'active',
                    panel.dataset.tab === tab
                );
            });
    }

    /**
     * Optional: get current tab
     */
    getActive() {
        return this.state.activeTab;
    }
}