class PeopleUI {

    constructor(scope) {
        this.scope = scope;

        this.cache = {
            container: null, // people grid (list)
            detail: null     // right panel
        };
    }

    /* ========================================
     * BIND / UNBIND
     * ====================================== */

    bind() {
        this.cache.container = document.querySelector('.people-grid');
        this.cache.detail    = document.querySelector('.people-detail');
    }

    unbind() {
        this.cache.container = null;
        this.cache.detail    = null;
    }

    /* ========================================
     * DIRECTORY (LIST)
     * ====================================== */

    renderListHTML(html) {
        if (!this.cache.container) return;

        this.cache.container.innerHTML = html;
    }

    /* ========================================
     * DETAIL VIEW (MAIN PANEL)
     * ====================================== */

    renderHTML(html) {
        if (!this.cache.detail) return;

        this.cache.detail.innerHTML = html;

        this.showDetailPanel();

        // 🔁 IMPORTANT: rebind dependent modules
        this.scope.emit('people.view.rendered');
    }

    clearDetail() {
        if (!this.cache.detail) return;

        this.cache.detail.innerHTML = `
            <div class="empty-state">
                Select a person
            </div>
        `;

        this.hideDetailPanel();
    }

    /* ========================================
     * TABS (SERVER-RENDERED)
     * ====================================== */

    renderTabHTML(tab, html) {
        const el = document.querySelector(
            `.tab-panel[data-tab="${tab}"]`
        );

        if (!el) return;

        el.innerHTML = html;
    }

    /* ========================================
     * STATE (VISUAL)
     * ====================================== */

    setActivePerson(personId) {
        document.querySelectorAll('.person-card')
            .forEach(el => el.classList.remove('selected'));

        const active = document.querySelector(
            `.person-card[data-person="${personId}"]`
        );

        active?.classList.add('selected');
    }

    updateFollowState(personId, isFollowing) {

        // card
        const card = document.querySelector(
            `.person-card[data-person="${personId}"]`
        );

        card?.classList.toggle('following', isFollowing);

        // detail view button
        const btn = document.querySelector(
            `.btn-follow[data-person="${personId}"]`
        );

        if (btn) {
            btn.textContent = isFollowing ? 'Following' : 'Follow';
        }
    }

    /* ========================================
     * PANEL CONTROL (MOBILE SUPPORT)
     * ====================================== */

    showDetailPanel() {
        this.cache.detail?.classList.add('active');
    }

    hideDetailPanel() {
        this.cache.detail?.classList.remove('active');
    }

    /* ========================================
     * LOADING STATES (OPTIONAL BUT IMPORTANT)
     * ====================================== */

    showLoading() {
        if (!this.cache.detail) return;

        this.cache.detail.innerHTML = `
            <div class="loading-state">
                Loading...
            </div>
        `;
    }

    showTabLoading(tab) {
        const el = document.querySelector(
            `.tab-panel[data-tab="${tab}"]`
        );

        if (!el) return;

        el.innerHTML = `
            <div class="loading-state small">
                Loading...
            </div>
        `;
    }
}