class PeopleAPI {

    constructor({ ui, loader, follow, realtime }) {
        this.ui            = ui;
        this.loader        = loader;
        this.followService = follow;
        this.realtime      = realtime;
    }

    /* ========================================
     * OPEN PERSON (HTML FLOW)
     * ====================================== */

    async openProfile(personId) {

        this.ui.showLoading();

        const html = await this.loader.loadPersonView(personId);

        this.ui.renderHTML(html);

        this.ui.setActivePerson(personId);

        return html;
    }

    /* ========================================
     * TAB CONTENT
     * ====================================== */

    async loadTab(personId, tab) {

        if (tab === 'profile') return null;
        
        console.log('Tab changed to '+tab);

        this.ui.showTabLoading(tab);

        const html = await this.loader.getTabContent(personId, tab);

        this.ui.renderTabHTML(tab, html);

        return html;
    }

    /* ========================================
     * FOLLOW SYSTEM
     * ====================================== */

    async follow(personId) {
        await this.followService.follow(personId);

        this.ui.updateFollowState(personId, true);

        // optional: invalidate cache so fresh data loads next time
        this.loader.invalidate(personId);
    }

    async unfollow(personId) {
        await this.followService.unfollow(personId);

        this.ui.updateFollowState(personId, false);

        this.loader.invalidate(personId);
    }

    async toggleFollow(personId, isFollowing) {
        return isFollowing
            ? this.unfollow(personId)
            : this.follow(personId);
    }

    async loadTree(personId, treeId) {
        const res = await this.loader.getTree(personId, treeId);
        return res.data;
    }
    
}