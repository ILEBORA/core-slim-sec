class PeopleRealtime {

    constructor(scope, ui, presence, notifications, follow, loader) {
        this.scope         = scope;
        this.ui            = ui;
        this.presence      = presence;
        this.notifications = notifications;
        this.follow        = follow;
        this.loader        = loader; // ✅ REQUIRED
    }

    initUserChannel() {
        this.scope.on('realtime.people', (event) => {
            this.handle(event);
        });
    }

    handle(event) {

        switch (event.type) {

            /* ========================================
             * FOLLOW / UNFOLLOW
             * ====================================== */

            case 'follow':
                this.ui.updateFollowState(event.personId, true);
                this.loader.invalidate(event.personId); // 🔥 CRITICAL
                break;

            case 'unfollow':
                this.ui.updateFollowState(event.personId, false);
                this.loader.invalidate(event.personId); // 🔥 CRITICAL
                break;

            /* ========================================
             * PRESENCE
             * ====================================== */

            case 'presence':
                this.presence.update(event);
                break;

            /* ========================================
             * PERSON UPDATE
             * ====================================== */

            case 'person.update':
                this.loader.invalidate(event.personId); // 🔥 instead of update()

                // optional: refresh if currently open
                const current = document.querySelector('.person-view');
                if (current && current.dataset.person == event.personId) {
                    this.scope.emit('people.person.open', {
                        personId: event.personId
                    });
                }

                break;
        }
    }

    destroy() {
        this.scope.off('realtime.people');
    }
}