var appNotifications = addPlugin(
    BoraPlugin,
    {
        pluginName: 'notifications',

        unreadCount: 0,

        init() {
            BoraPlugin.init.call(this);
            this.cacheDom();
            this.bindHooks();
        },

        cacheDom() {
            this.badge = document.querySelector('[data-app-badge="notifications"]');
            this.dropdown = document.querySelector('#app-notification-dropdown');
        },

        bindHooks() {
            const userId = window.MAIN_USER_ID;
            if (!userId) return;

            // 🔥 Inbox bumps
            // appHooks.addHook(
            //     'realtime:inbox:user:' + userId,
            //     e => this.handleInboxEvent(e)
            // );

            // 🔥 Activity / system can plug in later
            // appHooks.addHook('realtime:activity:user:' + userId, ...)
        },

        handleInboxEvent(e) {
            if (e.type !== 'thread.bumped') return;

            this.increment();

            // Optional toast
            alertBora.notify(
                'New message',
                e.preview || 'You received a message',
                4
            );

            // Optional dropdown insert
            this.addDropdownItem({
                title: 'New message',
                body: e.preview,
                time: e.time,
                link: `/portal/inbox/${e.thread_id}`
            });
        },

        increment(by = 1) {
            this.unreadCount += by;
            this.render();
        },

        set(count) {
            this.unreadCount = count;
            this.render();
        },

        clear() {
            this.unreadCount = 0;
            this.render();
        },

        render() {
            if (!this.badge) return;

            if (this.unreadCount > 0) {
                this.badge.textContent = this.unreadCount;
                this.badge.classList.remove('hidden');
            } else {
                this.badge.classList.add('hidden');
            }
        },

        addDropdownItem(item) {
            if (!this.dropdown) return;

            const el = document.createElement('li');
            el.innerHTML = `
                <a href="${item.link}">
                    <strong>${item.title}</strong>
                    <div>${item.body}</div>
                    <small>${item.time}</small>
                </a>
            `;

            this.dropdown.prepend(el);
        }
    }
);

appUI.notifications = addPlugin(
    BoraPlugin,
    {
        pluginName: 'notifications_ui',

        unreadCount: 0,

        init() {
            BoraPlugin.init.call(this);
            
        },
        clear(elem){
            alert('appUI Notifications Clear '+elem);
        },
        increment(elem){
            alert('appUI Notifications Increment '+elem);
        }

    }
);


// Init globally
document.addEventListener('DOMContentLoaded', () => {
    appUI.notifications.init();
});
