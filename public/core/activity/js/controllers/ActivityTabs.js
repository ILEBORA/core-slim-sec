class ActivityTabs {

    constructor(scope) {
        this.scope = scope;

        this.state = {
            activeTab: 'foryou'
        };
    }

    /**
     * Set active tab (called externally)
     */
    setTab(root, personId, tab) {
        if (!root || !tab) return;

        if (tab === this.state.activeTab) return;

        this.state.activeTab = tab;

        this.activate(root, tab);

        // notify system (API will load content)
        this.scope.emit('activity.tab.changed', {
            personId,
            tab
        });
    }

    /**
     * Apply UI state only
     */
    activate(root, tab) {

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

    getActive() {
        return this.state.activeTab;
    }
}