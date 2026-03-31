class InboxThreadLoader{

    constructor(scope, callbora, ui, typing, realtime){

        this.scope  = scope;
        this.callbora = callbora;
        this.ui     = ui;
        this.typing = typing;
        this.realtime = realtime

        // this.bindComposerSubmit(); // bind once
    }

    init() {
        this.bindComposerSubmit();
    }

    normalizeUrl(fullUrl){

        const base = window.__APP_BASE_PATH__ || '';

        fullUrl = String(fullUrl);

        if(base && fullUrl.startsWith(base)){
            fullUrl = fullUrl.slice(base.length);
        }

        fullUrl = fullUrl.split('?')[0];

        return fullUrl || '';
    }

    resolveThreadFromRoute(){

        const url = this.normalizeUrl(window.location.toString());

        const match = url.match(/portal\/inbox\/show\/(\d+)/);

        if(!match){
            this.ui.setView('list');
            return;
        }

        const threadId = match[1];

        // this.ui.setThreadSelected(threadId);

        // mark as read
        this.scope.emit('inbox.thread.read', {threadId: threadId});

        this.ui.setThreadSelected(threadId);
        this.scope.emit('inbox.thread.open', {threadId:threadId});

        // this.ui.setView('thread');

        // this.ui.setActiveThread(id);
        // this.realtime.subscribeThread(id);

        // this.load(threadId);
  
    }

    load(threadId){

        const container = document.querySelector('.messages');

        container.innerHTML = `<div class="loading">Loading conversation…</div>`;

        this.callbora
        .get(`api/modules/inbox/view-thread/${threadId}`)

        .then(res => {

            container.innerHTML = '';

            res.data.messages.forEach(msg => {

                container.insertAdjacentHTML(
                    'beforeend',
                    msg.html
                );

            });

            this.scope.emit('thread.participants.updated', {count:res.data.participants.length});

            this.ui.scrollBottom();

            this.typing.bind(threadId);

            this.ui.setThreadSelected(threadId);
            this.ui.clearThreadBadge(threadId);

            //
            history.pushState({}, '', `portal/inbox/show/${threadId}`);
            this.ui.bindScroll();

            // this.ui.setActiveThread(threadId);
            //
            $('.composer').data('thread',threadId);
            
            //TODO:: move to relevant controllers
            // 🔥 CLEAR UNREAD STATE
            let item = $(`.thread-item[data-thread="${threadId}"]`);
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
                header.querySelector('h4').textContent = res.data.thread.title ?? 'Chat with ' + res.data.thread.display_name ?? 'Conversation';
            }
            //
            const composer = document.querySelector('.composer');
            if(composer){
                composer.removeAttribute('hidden');
                composer.setAttribute('data-thread', threadId);
                composer.setAttribute(
                    'action',
                    `api/modules/inbox/send-message/${threadId}`
                );
            }

            let contextMenu = document.querySelector('.thread_context_menu');
            if(contextMenu){
                 contextMenu.setAttribute('data-context-id', threadId);
            }

            this.ui.setView('thread');
        })

        .catch(err => {

            console.error('[InboxLoader] failed', err);

            container.innerHTML =
                `<div class="error">Failed to load thread</div>`;

        });
    }

    bindComposerSubmit(){
        if (this._submitBound) return; // prevent duplicate binding
        document.addEventListener('submit', (e) => {

            const form = e.target.closest('.composer');
            if (!form) return;

            e.preventDefault();

            const input = form.querySelector('input[name="body"]');
            const body  = input.value.trim();
            if (!body) return;

            fetch(form.action, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({ body })
            })
            .then(async r => {
                const text = await r.text();
                if (!text) throw new Error('Empty response');
                return JSON.parse(text);
            })
            .then(res => {
                if (!res.success) {
                    alert('Message failed to send');
                    return;
                }
                input.value = '';
            })
            .catch(err => {
                console.error(err);
                alert('Network error');
            });

        });

        this._submitBound = true; // lock it

    }

}