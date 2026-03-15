class InboxThreadLoader{

    constructor(scope, callbora, ui, typing){

        this.scope  = scope;
        this.callbora = callbora;
        this.ui     = ui;
        this.typing = typing;
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

        this.ui.setView('thread');

        this.load(threadId);
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

            this.ui.scrollBottom();

            this.typing.bind(threadId);

            this.ui.setThreadSelected(threadId);
            this.ui.clearThreadBadge(threadId);

            //
            history.pushState({}, '', `portal/inbox/show/${threadId}`);
            this.ui.bindScroll();


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

            this.ui.setView('thread');

        })

        .catch(err => {

            console.error('[InboxLoader] failed', err);

            container.innerHTML =
                `<div class="error">Failed to load thread</div>`;

        });
    }

}