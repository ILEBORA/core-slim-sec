class PeoplePresence {

    constructor(ui) {
        this.ui = ui;

        // personId → presence data
        this.state = new Map();

        // optional debounce batching
        this.queue = new Map();
        this.flushTimer = null;
    }

    /**
     * Entry point from realtime
     */
    update(event) {
        if (!event || !event.personId) return;

        const personId = event.personId;

        const presence = {
            status: event.status || 'offline', // online | offline | away
            lastSeen: event.lastSeen || null
        };

        this.state.set(personId, presence);

        this.enqueue(personId, presence);
    }

    /**
     * Batch UI updates (important for bursts)
     */
    enqueue(personId, presence) {
        this.queue.set(personId, presence);

        if (this.flushTimer) return;

        this.flushTimer = setTimeout(() => {
            this.flush();
        }, 50); // small debounce
    }

    flush() {
        this.queue.forEach((presence, personId) => {
            this.applyToUI(personId, presence);
        });

        this.queue.clear();
        this.flushTimer = null;
    }

    /**
     * Apply presence to DOM
     */
    applyToUI(personId, presence) {
        const cards = document.querySelectorAll(
            `.person-card[data-id="${personId}"], 
             .person-view[data-person="${personId}"]`
        );

        cards.forEach(el => {
            this.updateStatusDot(el, presence);
            this.updateLastSeen(el, presence);
        });
    }

    /**
     * Update online/offline indicator
     */
    updateStatusDot(container, presence) {
        let dot = container.querySelector('.status-dot');

        if (!dot) {
            dot = document.createElement('span');
            dot.className = 'status-dot';
            container.appendChild(dot);
        }

        dot.classList.remove('online', 'offline', 'away');

        dot.classList.add(presence.status);
    }

    /**
     * Update "last seen"
     */
    updateLastSeen(container, presence) {
        let el = container.querySelector('.last-seen');

        if (!el) {
            el = document.createElement('div');
            el.className = 'last-seen';
            container.appendChild(el);
        }

        if (presence.status === 'online') {
            el.textContent = 'Online';
            return;
        }

        if (!presence.lastSeen) {
            el.textContent = 'Offline';
            return;
        }

        el.textContent = this.formatLastSeen(presence.lastSeen);
    }

    /**
     * Format time (can later move to helpers)
     */
    formatLastSeen(timestamp) {
        const diff = Date.now() - new Date(timestamp).getTime();

        const mins = Math.floor(diff / 60000);
        if (mins < 1) return 'Just now';
        if (mins < 60) return `${mins} min ago`;

        const hrs = Math.floor(mins / 60);
        if (hrs < 24) return `${hrs} hr ago`;

        const days = Math.floor(hrs / 24);
        return `${days} day${days > 1 ? 's' : ''} ago`;
    }

    /**
     * Optional: expose state
     */
    get(personId) {
        return this.state.get(personId) || null;
    }

    /**
     * Optional: preload presence (batch)
     */
    preload(list = []) {
        list.forEach(item => {
            if (!item.personId) return;

            this.state.set(item.personId, {
                status: item.status,
                lastSeen: item.lastSeen
            });
        });

        this.flush();
    }
}