__BORA_REGISTER_PLUGIN__(
'Inbox',
function(scope){

    const hooks      = scope.getService('hooks');
    const callbora   = scope.getService('callbora');
    const navigation = scope.getService('navigation');

    let threadId = null;
    let mounted  = false;
    let mainUserId = window.MAIN_USER_ID ?? null;

    /* ==========================================
       LIFECYCLE
    ========================================== */

    function mount(){

        if (mounted) return;
        mounted = true;

        bindUI();
        resolveThreadFromRoute();

        hooks.add('realtime:*', handleRealtimeWildcard);

        console.log('[Inbox] mounted');
    }

    function unmount(){

        if (!mounted) return;
        mounted = false;

        hooks.remove('realtime:*', handleRealtimeWildcard);

        threadId = null;

        console.log('[Inbox] unmounted');
    }

    /* ==========================================
       ROUTE HANDLING
    ========================================== */

    function normalizeUrl(fullUrl){
        const base = window.__APP_BASE_PATH__ || '';

        if (!fullUrl) return '/';

        fullUrl = String(fullUrl);

        if (base && fullUrl.startsWith(base)){
            fullUrl = fullUrl.slice(base.length);
        }

        // remove query
        fullUrl = fullUrl.split('?')[0];

        // if (!fullUrl.startsWith('/')){
        //     fullUrl = '/' + fullUrl;
        // }

        return fullUrl || '';
    }

    function resolveThreadFromRoute(){

        const url = normalizeUrl(window.location); alert(url);
        const match = url.match(/\portal\/inbox\/show\/(\d+)/);

        if (!match) {
            setView('list');
            return;
        }

        threadId = match[1];
        setView('thread');
        loadThread(threadId);
    }

    function openThread(id){

        if (!id) return;

        navigation.go(`portal/inbox/show/${id}`);
    }

    /* ==========================================
       THREAD LOADING
    ========================================== */

    function loadThread(id){

        const container = document.querySelector('.messages');
        if (!container) return;

        container.innerHTML = `<div class="loading">Loading conversation…</div>`;

        new CallBora(`api/modules/inbox/view-thread/${id}`)
            .setMethod("GET")
            .setCallback((res)=>{

                if (!res.success){
                    container.innerHTML = `<p>Failed to load thread</p>`;
                    return;
                }

                container.innerHTML = '';

                const messages = res.data.messages || [];

                messages.forEach(msg=>{
                    container.insertAdjacentHTML(
                        'beforeend',
                        renderMessage(msg)
                    );
                });

                scrollBottom();
                bindThreadMeta(id, res);

            })
            .build();
    }

    /* ==========================================
       UI BINDING
    ========================================== */

    function bindUI(){
        alert('inbox');
        document.addEventListener('click', handleClick);
        document.addEventListener('keydown', handleKeyNav);
    }

    function handleClick(e){

        const threadItem = e.target.closest('.thread-item');
        if (threadItem){

            const id = threadItem.dataset.thread;
            if (!id) return;

            highlightThread(threadItem);
            openThread(id);
            return;
        }

        const backBtn = e.target.closest('.back-btn');
        if (backBtn){
            setView('list');
            navigation.go('portal/inbox');
            return;
        }

        const startBtn = e.target.closest('[data-action="inbox:start"]');
        if (startBtn){
            startConversation();
            return;
        }

        const fab = e.target.closest('.fab-new-thread');
        if (fab){
            startConversation();
            return;
        }
    }

    function handleKeyNav(e){

        if (!['ArrowUp','ArrowDown','Enter'].includes(e.key)) return;

        const list = document.querySelector('.thread-list');
        if (!list) return;

        const items = [...list.querySelectorAll('.thread-item')]
            .filter(i => i.style.display !== 'none');

        if (!items.length) return;

        let index = items.findIndex(i => i.classList.contains('selected'));

        if (e.key === 'ArrowDown') index = Math.min(index + 1, items.length - 1);
        if (e.key === 'ArrowUp')   index = Math.max(index - 1, 0);

        if (e.key === 'Enter' && index >= 0){
            items[index].click();
            return;
        }

        items.forEach(i => i.classList.remove('selected'));
        items[index]?.classList.add('selected');
        items[index]?.scrollIntoView({ block: 'nearest' });
    }

    function highlightThread(item){

        document
            .querySelectorAll('.thread-item.active')
            .forEach(el => el.classList.remove('active'));

        item.classList.add('active');
    }

    function setView(view){

        const layout = document.querySelector('.inbox-layout');
        layout?.setAttribute('data-view', view);
    }

    /* ==========================================
       REALTIME
    ========================================== */

    function handleRealtimeWildcard(eventName, e){

        if (!mounted) return;
        if (!eventName.startsWith('realtime:inbox:')) return;

        if (eventName === `realtime:inbox:thread:${threadId}`){
            appendMessage(e);
        }
    }

    /* ==========================================
       MESSAGE RENDERING
    ========================================== */

    function renderMessage(msg){

        const tpl = document.getElementById('tpl-inbox-message');
        if (!tpl) return '';

        return tpl.innerHTML
            .replace(/\{\{\s*body\s*\}\}/g, escape(msg.body ?? ''));
    }

    function appendMessage(msg){

        const container = document.querySelector('.messages');
        if (!container) return;

        container.insertAdjacentHTML(
            'beforeend',
            renderMessage(msg)
        );

        scrollBottom();
    }

    function scrollBottom(){

        const c = document.querySelector('.messages-cont');
        if (c) c.scrollTop = c.scrollHeight + 40;
    }

    /* ==========================================
       START CONVERSATION
    ========================================== */

    function startConversation(){

        fetch('api/modules/inbox/thread', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                thread_type: 'chat',
                title: 'New Conversation'
            })
        })
        .then(r => r.json())
        .then(res => {
            if (res.success && res.data.thread){
                openThread(res.data.thread.id);
            }
        });
    }

    function escape(text){
        const div = document.createElement('div');
        div.textContent = text ?? '';
        return div.innerHTML;
    }

    return { mount, unmount };

},
{
    requires:['hooks','callbora','permissions','face','navigation'],
    activateOn: (route) => route.startsWith('portal/inbox'),
    permission: { group:'inbox', sub:'view' }
});