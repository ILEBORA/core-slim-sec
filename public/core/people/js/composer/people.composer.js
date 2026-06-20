class PeopleComposer {

    constructor(helpers) {
        this.helpers = helpers;
    }

    /**
     * =========================
     * PERSON CARD (GRID/LIST)
     * =========================
     */
    personCard(person) {
        const name   = this.helpers.getDisplayName(person);
        const avatar = this.helpers.resolveAvatar(person);

        return `
            <div class="person-card"
                 data-person="${person.id}">

                <div class="avatar">
                    <img class="personAvatar{{ person.id }}" src="${avatar}" alt="${name}" />

                    <span class="status-dot ${person.presence?.status || 'offline'}"></span>
                </div>

                <div class="name">${name}</div>
            </div>
        `;
    }

    /**
     * =========================
     * PERSON HEADER (DETAIL)
     * =========================
     */
    personHeader(person) {
        const name   = this.helpers.getDisplayName(person);
        const avatar = this.helpers.resolveAvatar(person);

        return `
            <header class="person-header">

                <button class="back-btn">←</button>

                <div class="person-info">
                    <h4>${name}</h4>
                    <div class="last-seen">
                        ${this.renderPresenceText(person)}
                    </div>
                </div>

                <div class="actions">
                    ${this.renderFollowButton(person)}
                </div>

            </header>
        `;
    }

    /**
     * =========================
     * PROFILE SUMMARY BLOCK
     * =========================
     */
    profileSummary(person) {
        const name   = this.helpers.getDisplayName(person);
        const avatar = this.helpers.resolveAvatar(person);

        return `
            <div class="person-profile">

                <div class="avatar-large">
                    <img src="${avatar}" />
                </div>

                <div class="details">
                    <h3>${name}</h3>

                    <div class="meta">
                        ${person.bio || ''}
                    </div>
                </div>

            </div>
        `;
    }

    /**
     * =========================
     * FOLLOW BUTTON
     * =========================
     */
    renderFollowButton(person) {
        if (!this.helpers.isFollowable(person)) {
            return '';
        }

        const label = person.is_following ? 'Following' : 'Follow';

        return `
            <button class="btn-follow"
                    data-person="${person.id}">
                ${label}
            </button>
        `;
    }

    /**
     * =========================
     * PRESENCE TEXT
     * =========================
     */
    renderPresenceText(person) {
        const presence = person.presence;

        if (!presence) return '';

        if (presence.status === 'online') {
            return 'Online';
        }

        if (presence.lastSeen) {
            return `Last seen ${this.formatLastSeen(presence.lastSeen)}`;
        }

        return 'Offline';
    }

    formatLastSeen(timestamp) {
        const diff = Date.now() - new Date(timestamp).getTime();

        const mins = Math.floor(diff / 60000);
        if (mins < 1) return 'just now';
        if (mins < 60) return `${mins} min ago`;

        const hrs = Math.floor(mins / 60);
        if (hrs < 24) return `${hrs} hr ago`;

        const days = Math.floor(hrs / 24);
        return `${days} day${days > 1 ? 's' : ''} ago`;
    }

    /**
     * =========================
     * FULL DETAIL VIEW (OPTIONAL)
     * =========================
     */
    personView(person) {
        return `
            <div class="person-view" data-person="${person.id}">

                ${this.personHeader(person)}

                <nav class="person-tabs">
                    <button data-tab="profile" class="active">Profile</button>
                    <button data-tab="tree">Family</button>
                    <button data-tab="activity">Activity</button>
                    <button data-tab="events">Events</button>
                </nav>

                <div class="person-content">

                    <div class="tab-panel active" data-tab="profile">
                        ${this.profileSummary(person)}
                    </div>

                    <div class="tab-panel" data-tab="tree">
                        <div lvui="people_tree_${person.id}"></div>
                    </div>

                    <div class="tab-panel" data-tab="activity">
                        <div lvui="people_activity_${person.id}"></div>
                    </div>

                    <div class="tab-panel" data-tab="events">
                        <div lvui="people_events_${person.id}"></div>
                    </div>

                </div>

            </div>
        `;
    }
}