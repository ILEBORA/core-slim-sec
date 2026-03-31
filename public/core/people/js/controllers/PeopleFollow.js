class PeopleFollow {

    constructor(callbora, ui, loader) {
        this.callbora = callbora;
        this.ui       = ui;
        this.loader   = loader;
    }

    /* ========================================
     * FOLLOW
     * ====================================== */

    async follow(personId) {

        // optimistic UI
        this.ui.updateFollowState(personId, true);

        try {
            await this.callbora.post(
                `api/modules/people/person/${personId}/follow`
            );

            // invalidate cached HTML so next load is fresh
            this.loader.invalidate(personId);

        } catch (err) {
            // rollback UI on failure
            this.ui.updateFollowState(personId, false);
            throw err;
        }
    }

    /* ========================================
     * UNFOLLOW
     * ====================================== */

    async unfollow(personId) {

        this.ui.updateFollowState(personId, false);

        try {
            await this.callbora.post(
                `api/modules/people/person/${personId}/unfollow`
            );

            this.loader.invalidate(personId);

        } catch (err) {
            this.ui.updateFollowState(personId, true);
            throw err;
        }
    }

    /* ========================================
     * TOGGLE
     * ====================================== */

    async toggle(personId, isFollowing) {
        return isFollowing
            ? this.unfollow(personId)
            : this.follow(personId);
    }
}