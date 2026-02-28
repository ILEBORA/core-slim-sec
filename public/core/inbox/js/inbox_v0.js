const appInbox = addPlugin(
    BoraPlugin,
    {
        pluginName: 'inbox',

        init: function () {
            BoraPlugin.init.call(this);

            this.threadId = document
                .querySelector('.thread-view')
                ?.dataset.thread;

            this.mainUserId = window.MAIN_USER_ID ?? null;

            if (!this.threadId) {
                if (this.debug) {
                    console.warn('[appInbox] No active thread');
                }
                return;
            }

            this.registerHooks();

            if (this.debug) {
                console.log('[appInbox] Initialized for thread', this.threadId);
            }

            //Scroll to bottom
            let container = document.querySelector('.messages-cont');
            if (container){
                container.scrollTop = container.scrollHeight + 40;
            }
        },

        /* ---------------------------------
         | Hooks
         |---------------------------------*/

        registerHooks: function () {
            appHooks.addHook(
                'realtime:inbox:thread:' + this.threadId,
                this.handleRealtime.bind(this) // 👈 CRITICA//e => this.handleRealtime(e)
            );

            // this.initInboxRealtime();
        },

        handleRealtime: function (e) {
            if (!e || !e.type) return;
            console.log('HANDLER FOR:: ',e);
            switch (e.type) {
                case 'message.sent':
                    // alert(this.mainUse  rId);
                    console.log('message.sent called by '+e.sender_id +' from ' + this.mainUserId);
                    this.appendMessage(e, {
                        isMe: e.sender_id === this.mainUserId
                    });
                    break;

                case 'typing.start':
                    this.showTyping();
                    break;

                case 'typing.stop':
                    this.hideTyping();
                    break;
            }
        },

        /* ---------------------------------
         | Thread list updates
         |---------------------------------*/

        bumpThread: function (threadId, data = {}) {
            const item = document.querySelector(
                `.thread-item[data-thread="${threadId}"]`
            );
            if (!item) return;

            item.parentNode.prepend(item);

            if (data.preview) {
                item.querySelector('.preview').textContent = data.preview;
            }

            if (data.time) {
                item.querySelector('time').textContent = data.time;
            }

            item.classList.add('unread');

            let badge = item.querySelector('.badge');
            if (!badge) {
                badge = document.createElement('span');
                badge.className = 'badge';
                badge.textContent = '1';
                item.querySelector('.stats')?.prepend(badge);
            } else {
                badge.textContent = parseInt(badge.textContent, 10) + 1;
            }

            const search = document.querySelector('.thread-search input')?.value;
            if (search) {
                const event = new Event('input');
                document.querySelector('.thread-search input')?.dispatchEvent(event);
            }
        },

        markThreadRead: function (threadId) {
            const item = document.querySelector(
                `.thread-item[data-thread="${threadId}"]`
            );
            if (!item) return;

            item.classList.remove('unread');
            item.querySelector('.badge')?.remove();
        },

        /* ---------------------------------
         | Messages
         |---------------------------------*/
        soundOn: true,
        appendMessage: function (message, { isMe = false } = {}) {
            // console.log('NEW MESSAGE::',message);
            const container = document.querySelector('.messages');
            if (!container || !message?.body) return;

            if (
                message.id &&
                container.querySelector(`[data-message="${message.id}"]`)
            ) {
                return;
            }

            const el = document.createElement('div');
            el.className = 'message ' + (isMe ? 'outgoing' : 'incoming');
            if (message.id) el.dataset.message = message.id;

            el.innerHTML = `
                <div class="bubble">${this.escape(message.body)}</div>
            `;

            container.appendChild(el);
            // container.scrollTop = container.scrollHeight + 40;
            //Scroll to bottom
            let messages_cont = document.querySelector('.messages-cont');
            if (messages_cont){
                messages_cont.scrollTop = messages_cont.scrollHeight + 40;
            }

            console.log('isMe:: ',isMe);
            if(this.soundOn && !isMe){
                // Play sound
                var audio = new Audio('assets/sound/doink.mp3');
                audio.play();
            }
        },

        /* ---------------------------------
         | Typing indicator
         |---------------------------------*/

        showTyping: function () {
            document.querySelector('.typing-indicator')?.removeAttribute('hidden');
        },

        hideTyping: function () {
            document.querySelector('.typing-indicator')?.setAttribute('hidden', true);
        },

        openNewThread: function(){
            appInboxComposer.init();
            appInboxComposer.open();
        },

        openThread: function(threadId){
            const container = document.querySelector('.messages');
            if (!container) return;

            container.innerHTML = `
                <div class="loading">Loading conversation…</div>
            `;

            new CallBora(`api/modules/inbox/view-thread/${threadId}`)
            .setMethod("GET")
            .setParams({})
            .setCallback((res) => {
                if (!res.success) {
                    container.innerHTML = `<p>Failed to load thread</p>`;
                    return;
                }

                // container.innerHTML = res.data.messages;
                const messages = res.data.messages || [];

                container.innerHTML = ''; // clear loading

                messages.forEach(msg => {
                    container.insertAdjacentHTML(
                        'beforeend',
                        InboxTemplate.renderMessage(msg)
                    );
                });

                // Scroll once, after all inserts
                //Scroll to bottom
                let container2 = document.querySelector('.messages-cont');
                if (container2){
                    container2.scrollTop = container2.scrollHeight + 40;
                }

                // 🔥 critical: rebind realtime hooks for this thread
                this.bindThread(threadId, res);
            })
            .setDone(() => {
                console.log("Request finished");
                //Hide Overlay
            })
            .setError((xhr) => {
                console.error("Error:", xhr);
                container.html("<p style='color:red'>Failed to load.</p>");
            })
            .build();
        },
        bindThread: function(threadId, res){
            console.log('Bind');
            $('.thread-item').removeClass('selected');
            const item = $(`.thread-item[data-thread="${threadId}"]`);
            item.addClass('selected');
            
            $('.composer').data('thread',threadId);
            
            // 🔥 CLEAR UNREAD STATE
            item.removeClass('unread');
            item.find('.badge').remove();
            // appUI.notifications.clear('inbox');

            const thread = document.querySelector('.thread-view');
            if(thread){
                 thread.setAttribute('data-thread', threadId);
            }

            //
            const header = document.querySelector('.thread-header');
            if(header){
                header.setAttribute('data-thread', threadId);
                header.querySelector('h4').textContent = res.data.thread.title ?? 'Conversation';
            }

            const composer = document.querySelector('.composer');
            if(composer){
                composer.removeAttribute('hidden');
                composer.setAttribute('data-thread', threadId);
                composer.setAttribute(
                    'action',
                    `api/modules/inbox/send-message/${threadId}`
                );
            }

        },

        initInboxRealtime() { 
            const userId = window.MAIN_USER_ID;// window.MAIN_USER_ID;
            // alert('here ');
            if(!userId) return;
            appHooks.addHook('realtime:inbox:user:' + userId, e => {
                console.log('[Inbox realtime user event]', e);

                if (e.type !== 'thread.bumped') return;

                const { thread_id, preview, time } = e;
                // alert(thread_id);
                const item = document.querySelector(
                    `.thread-item[data-thread="${thread_id}"]`
                );

                const inboxCont = $('.inbox-layout');
                if(inboxCont.length){ // If within the inbox view
                    //If thread does not exist create it
                    if (!item) {
                        item = appInbox.createThreadItem({
                            thread_id,
                            preview,
                            time
                        });
                    }else{
                        //Element found
                        const isActive = item.classList.contains('selected');

                        // Update preview
                        const previewEl = item.querySelector('.preview');
                        if (previewEl) previewEl.textContent = preview;

                        // Update time
                        const timeEl = item.querySelector('time');
                        if (timeEl) timeEl.textContent = time;

                        // 🔥 Badge only if NOT active
                        if (!isActive && inboxCont.length) {
                            appInbox.bumpThread(thread_id);

                            
                            // // Optional alert
                            // alertBora.set('notifierPosition', 'top-right').set('notifierDelay', 10);
                            // alertBora.notify('You have received a new inbox message', 'success', 20);
                            
                            //  if(appInbox.soundOn){
                            //     // Play sound
                            //     var audio = new Audio('assets/sound/doink.mp3');
                            //     audio.play();
                            // }

                        }
                    }

                }else{ //Outside the Inbox view
                    // Optional alert
                    // alertBora.notify(
                    //     'New message',
                    //     preview || 'You received a message',
                    //     4
                    // );
                    alertBora.set('notifierPosition', 'top-right').set('notifierDelay', 10);
                    alertBora.notify('You have received a new inbox message', 'success', 20);
                            
                    if(appInbox.soundOn){
                        // Play sound
                        // var audio = new Audio('assets/sound/doink.mp3');
                        // audio.play();
                    }
                    
                    //Finally
                    // Optional global app badge
                    //appUI.notifications.increment('inbox');
                }
            });
        },
        createThreadItem: function ({ thread_id, preview, time }) {
            const list = document.querySelector('.thread-list');
            if (!list) return null;

            const li = document.createElement('li');
            li.className = 'thread-item unread';
            li.dataset.thread = thread_id;

            li.innerHTML = `
                <div class="avatar">
                    <span class="status-dot online"></span>
                </div>

                <div class="meta">
                    <div class="title">Conversation...</div>
                    <div class="preview">${preview ?? ''}</div>
                </div>

                <div class="stats">
                    <span class="badge">1</span>
                    <time>${time ?? ''}</time>
                </div>
            `;

            list.prepend(li);
            return li;
        },
        
        /* ---------------------------------
         | Utilities
         |---------------------------------*/

        escape: function (text) {
            const div = document.createElement('div');
            div.textContent = text ?? '';
            return div.innerHTML;
        },

        focus(){
            //Focus
            const layout = document.querySelector('.inbox-layout');

            const observer = new MutationObserver(() => {
                if (layout?.getAttribute('data-view') === 'list') {
                    document
                        .querySelector('.thread-search input')
                        ?.focus();
                }
            });

            observer.observe(layout, { attributes: true });

        },

        initFilters(){

        }
    }
);

const appInboxComposer = addPlugin(BoraPlugin, {
    pluginName: 'inboxComposer',

    init() {
        this.el = document.querySelector('.inbox-composer');
        if (!this.el) return;

        this.bind();
    },

    bind() {
        this.el.querySelector('.close')
            ?.addEventListener('click', () => this.close());

        this.el.querySelector('.composer-backdrop')
            ?.addEventListener('click', () => this.close());

        const input = this.el.querySelector('.participant-search');
        const list  = this.el.querySelector('.participant-results');

        let timer;

        input.addEventListener('input', () => {
            clearTimeout(timer);

            const q = input.value.trim();
            if (q.length < 2) {
                list.innerHTML = '';
                return;
            }

            timer = setTimeout(() => {
                fetch(`api/modules/inbox/participants?q=${encodeURIComponent(q)}`)
                    .then(r => r.json())
                    .then(res => this.renderResults(res.data || []));
            }, 250);
        });
    },

    open() {
        this.el.hidden = false;
        this.el.classList.add('open');
        this.el.querySelector('.participant-search')?.focus();

        this.el.querySelector('.start-btn')
            .addEventListener('click', () => {
                if (!this.selectedUser) return;

                fetch('api/modules/inbox/create-direct', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify({
                        user_id: this.selectedUser.id
                    })
                })
                .then(r => r.json())
                .then(res => {
                    if (!res.success) return;

                    this.close();

                    // navigate / load thread
                    window.location.href =
                        `portal/inbox/show/${res.thread.id}`;
                });
            });
    },

    close() {
        this.el.classList.remove('open');
        setTimeout(() => {
            this.el.hidden = true;
        }, 250);
    },
    renderResults(users) {
        const list = this.el.querySelector('.participant-results');
        list.innerHTML = '';

        users.forEach(u => {
            const li = document.createElement('li');
            li.textContent = `${u.username} (${u.email})`;
            li.dataset.id = u.id;

            li.addEventListener('click', () => {
                this.selectUser(u);
            });

            list.appendChild(li);
        });
    },

    selectUser(user) {
        this.selectedUser = user;

        this.el.querySelectorAll('.participant-results li')
            .forEach(li => li.classList.remove('selected'));

        event.target.classList.add('selected');

        this.el.querySelector('.start-btn').disabled = false;
    },
});

appInboxComposer.init();

document.addEventListener('DOMContentLoaded', () => {
    const match = location.pathname.match(/\/portal\/inbox\/(\d+)/);
    if (!match) return;

    const threadId = match[1];

    const layout = document.querySelector('.inbox-layout');
    layout?.setAttribute('data-view', 'thread');

    appInbox.openThread(threadId);

    const item = document.querySelector(
        `.thread-item[data-thread="${threadId}"]`
    );
    item?.classList.add('active');
});

window.addEventListener('popstate', e => {
    const state = e.state;

    if (!state || !state.threadId) {
        // Back to list
        document
            .querySelector('.inbox-layout')
            ?.setAttribute('data-view', 'list');
        return;
    }

    appInbox.openThread(state.threadId);
});

const InboxTemplate = {

    renderMessage(message) {
        return TreeTemplateRegistry.render(
            'inbox-message',
            {
                id: message.id,
                body: message.body,
                classes: message.sender_id === window.MAIN_USER_ID
                        ? 'outgoing'
                        : 'incoming'
            }
        );
    }

};

document.addEventListener('DOMContentLoaded', () => {
    appInbox.initInboxRealtime();
});