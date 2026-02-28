__BORA_REGISTER_PLUGIN__(
'Inbox',
function(scope){

    const hooks = scope.getService('hooks');
    const callbora = scope.getService('callbora');

    let threadId = null;
    let mainUserId = window.MAIN_USER_ID ?? null;
    let soundOn = true;

    let mounted = false;

    /* =========================
       LIFECYCLE
    ========================= */

    function mount(){

        if(mounted) return;
        mounted = true;

        resolveThreadFromRoute();
        hooks.add('realtime:*', handleRealtimeWildcard);

        console.log('[Inbox] mounted');
    }

    function unmount(){

        if(!mounted) return;
        mounted = false;

        hooks.remove('realtime:*', handleRealtimeWildcard);

        threadId = null;

        console.log('[Inbox] unmounted');
    }

    /* =========================
       ROUTE RESOLUTION
    ========================= */

    function resolveThreadFromRoute(){

        const url = window.location.pathname;
        const match = url.match(/\/portal\/inbox\/show\/(\d+)/);

        if(!match) return;

        threadId = match[1];
        initThreadView(threadId);
    }

    /* =========================
       THREAD INIT
    ========================= */

    function initThreadView(id){

        const container = document.querySelector('.messages');
        if(!container) return;

        container.innerHTML = `<div class="loading">Loading conversation…</div>`;

        new CallBora(`api/modules/inbox/view-thread/${id}`)
            .setMethod("GET")
            .setParams({})
            .setCallback((res)=>{
                if(!res.success){
                    container.innerHTML = `<p>Failed to load thread</p>`;
                    return;
                }

                container.innerHTML = '';

                const messages = res.data.messages || [];

                messages.forEach(msg=>{
                    container.insertAdjacentHTML(
                        'beforeend',
                        InboxTemplate.renderMessage(msg)
                    );
                });

                scrollBottom();
                bindThreadUI(id, res);
            })
            .build();
    }

    /* =========================
       REALTIME
    ========================= */

    function handleRealtimeWildcard(eventName, e){

        if(!mounted) return;
        if(!eventName.startsWith('realtime:inbox:')) return;

        if(eventName === `realtime:inbox:thread:${threadId}`){
            handleThreadRealtime(e);
        }

        if(eventName === `realtime:inbox:user:${mainUserId}`){
            handleUserRealtime(e);
        }
    }

    function handleThreadRealtime(e){

        if(!e?.type) return;

        switch(e.type){

            case 'message.sent':
                appendMessage(e, {
                    isMe: e.sender_id === mainUserId
                });
                break;

            case 'typing.start':
                showTyping();
                break;

            case 'typing.stop':
                hideTyping();
                break;
        }
    }

    function handleUserRealtime(e){

        if(e.type !== 'thread.bumped') return;

        bumpThread(e.thread_id, e);
    }

    /* =========================
       UI LOGIC
    ========================= */

    function appendMessage(message, { isMe = false } = {}){

        const container = document.querySelector('.messages');
        if(!container || !message?.body) return;

        if(message.id &&
           container.querySelector(`[data-message="${message.id}"]`)
        ){
            return;
        }

        const el = document.createElement('div');
        el.className = 'message ' + (isMe ? 'outgoing' : 'incoming');
        if(message.id) el.dataset.message = message.id;

        el.innerHTML = `
            <div class="bubble">${escape(message.body)}</div>
        `;

        container.appendChild(el);
        scrollBottom();

        if(soundOn && !isMe){
            new Audio('assets/sound/doink.mp3').play();
        }
    }

    function bumpThread(threadId, data){

        const item = document.querySelector(
            `.thread-item[data-thread="${threadId}"]`
        );
        if(!item) return;

        item.parentNode.prepend(item);
        item.classList.add('unread');
    }

    function bindThreadUI(threadId, res){
        const composer = document.querySelector('.composer');
        if (composer) {
            composer.setAttribute('data-thread', threadId);
        }

        const headerEl = document.querySelector('.thread-header h4');
        if (headerEl) {
            headerEl.textContent = res?.data?.thread?.title ?? 'Conversation';
        }
    }

    function scrollBottom(){
        const c = document.querySelector('.messages-cont');
        if(c) c.scrollTop = c.scrollHeight + 40;
    }

    function showTyping(){
        document.querySelector('.typing-indicator')
            ?.removeAttribute('hidden');
    }

    function hideTyping(){
        document.querySelector('.typing-indicator')
            ?.setAttribute('hidden', true);
    }

    function escape(text){
        const div = document.createElement('div');
        div.textContent = text ?? '';
        return div.innerHTML;
    }

    return { mount, unmount };

},
{
    requires:['hooks','callbora','permissions','face'],
    activateOn: (route) => route.startsWith('/portal/inbox'),
    permission: { group:'inbox', sub:'view' }
});