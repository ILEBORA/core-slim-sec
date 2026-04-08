__BORA_REGISTER_PLUGIN__(
'Inbox',
function(scope){

/* =========================================================
   STATE
========================================================= */

const state = {
    mounted:false,
    threadId:null,
    threadHook:null,
    mainUserId: rd('uID') ?? window.MAIN_USER_ID ?? null,
    loadingHistory:false
};

/* =========================================================
   LIFECYCLE
========================================================= */

function mount(){

    if(state.mounted) return;
    state.mounted = true;

    bindUI();
    initUserRealtime();
    resolveThreadFromRoute();

    console.log('[Inbox] mounted');
}

function unmount(){

    if(!state.mounted) return;

    state.mounted = false;

    $(document).off('.inbox');

    if(state.threadHook){
        scope.off(state.threadHook, handleRealtime);
        state.threadHook = null;
    }

    state.threadId = null;

    console.log('[Inbox] unmounted');
}

/* =========================================================
   ROUTING
========================================================= */

function resolveThreadFromRoute(){

    const url = normalizeUrl(window.location);
    const match = url.match(/portal\/inbox\/thread\/(\d+)/);

    if(!match){
        setView('list');
        return;
    }

    state.threadId = match[1];

    setView('thread');

    loadThread(state.threadId);
}

function normalizeUrl(fullUrl){

    const base = window.__APP_BASE_PATH__ || '';

    fullUrl = String(fullUrl);

    if(base && fullUrl.startsWith(base)){
        fullUrl = fullUrl.slice(base.length);
    }

    fullUrl = fullUrl.split('?')[0];

    return fullUrl || '';
}

/* =========================================================
   REALTIME
========================================================= */

function initUserRealtime(){

    const userId = state.mainUserId;
    if(!userId) return;

    scope.on(`realtime:inbox:user:${userId}`, handleUserRealtime);
}

function subscribeThreadRealtime(id){

    if(state.threadHook){
        scope.off(state.threadHook, handleRealtime);
    }

    state.threadHook = `realtime:inbox:thread:${id}`;

    scope.on(state.threadHook, handleRealtime);

    console.log('[Inbox] subscribed', state.threadHook);
}

function handleUserRealtime(e){

    const data = e?.payload;
    if(!data) return;

    if(data.type !== 'thread.bumped') return;

    updateThreadPreview(data);
}

function handleRealtime(e){

    const data = e?.payload;
    if(!data) return;

    switch(data.type){

        case 'message.sent':
            appendMessage(data);
        break;

        case 'typing.start':
            showTyping();
        break;

        case 'typing.stop':
            hideTyping();
        break;
    }
}

/* =========================================================
   THREAD LOADING
========================================================= */

function loadThread(id){

    const container = document.querySelector('.messages');
    if(!container) return;

    container.innerHTML = `<div class="loading">Loading conversation…</div>`;

    new CallBora(`api/modules/inbox/view-thread/${id}`)
        .setMethod("GET")
        .setCallback(res=>{

            if(!res.success){
                container.innerHTML = `<p>Failed to load thread</p>`;
                return;
            }

            container.innerHTML = '';

            (res.data.messages || []).forEach(msg=>{
                container.insertAdjacentHTML('beforeend', msg.html);
            });

            scrollBottom();

            bindThread(id,res);

            subscribeThreadRealtime(id);

        })
        .setDone(()=>{
            history.pushState({},'',`portal/inbox/thread/${id}`);
            bindScroll();
        })
        .build();
}

/* =========================================================
   THREAD PREVIEW
========================================================= */

function updateThreadPreview({thread_id, preview, time}){

    const item = document.querySelector(
        `.thread-item[data-thread="${thread_id}"]`
    );

    const inboxView = document.querySelector('.inbox-layout');

    if(!inboxView){
        alertBora.notify(
            'New message',
            preview || 'You received a message',
            4
        );
        return;
    }

    if(!item){
        createThreadItem({thread_id,preview,time});
        return;
    }

    const previewEl = item.querySelector('.preview');
    if(previewEl) previewEl.textContent = preview;

    const timeEl = item.querySelector('time');
    if(timeEl) timeEl.textContent = time;

    if(!item.classList.contains('selected')){
        appInbox.bumpThread(thread_id);
    }
}

/* =========================================================
   DOM RENDERING
========================================================= */

function appendMessage(msg){

    const container = document.querySelector('.messages');
    if(!container) return;

    if(document.querySelector(`[data-message-id="${msg.id}"]`)){
        return;
    }

    container.insertAdjacentHTML('beforeend', msg.html);

    scrollBottom();
}

function createThreadItem({thread_id,preview,time}){

    const list = document.querySelector('.thread-list');
    if(!list) return;

    const li = document.createElement('li');

    li.className = 'thread-item unread';
    li.dataset.thread = thread_id;

    li.innerHTML = `
        <div class="avatar"></div>
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
}

/* =========================================================
   UI
========================================================= */

function bindUI(){

    bindSearch();

    $(document)
        .off('.inbox')
        .on('click.inbox','.thread-item',handleThreadClick)
        .on('click.inbox','.back-btn',handleBack)
        .on('click.inbox','.fab-new-thread',openNewThread)
        .on('keydown.inbox',handleKeyNav);
}

function handleThreadClick(){

    const id = $(this).data('thread');
    if(!id) return;

    highlightThread(this);
    setView('thread');
    loadThread(id);
}

function handleBack(){
    setView('list');
    history.pushState({},'', 'portal/inbox');
}

async function openNewThread(){

    const composer = await scope.getPlugin('InboxComposer');

    composer?.mount?.();
    composer?.open?.();
}

/* =========================================================
   HELPERS
========================================================= */

function scrollBottom(){

    const c = document.querySelector('.messages-cont');

    if(c) c.scrollTop = c.scrollHeight + 40;
}

function setView(view){

    const layout = document.querySelector('.inbox-layout');

    layout?.setAttribute('data-view',view);
}

function highlightThread(item){

    document
        .querySelectorAll('.thread-item.active')
        .forEach(el=>el.classList.remove('active'));

    item.classList.add('active');
}

function showTyping(){
    document.querySelector('.typing-indicator')
        ?.removeAttribute('hidden');
}

function hideTyping(){
    document.querySelector('.typing-indicator')
        ?.setAttribute('hidden',true);
}

function bindScroll(){

    const container = document.querySelector('.messages-cont');

    container?.addEventListener('scroll',()=>{
        if(container.scrollTop < 50){
            loadPreviousMessages();
        }
    });
}

function bindSearch(){

    const el = document.querySelector('.inbox-composer');
    if(!el || el.dataset.bound) return;

    el.dataset.bound = '1';

    const input = el.querySelector('.participant-search');
    const list  = el.querySelector('.participant-results');

    let timer;

    input.addEventListener('input',()=>{

        clearTimeout(timer);

        const q = input.value.trim();

        if(q.length < 2){
            list.innerHTML = '';
            return;
        }

        timer = setTimeout(()=>{

            fetch(`api/modules/inbox/participants?q=${encodeURIComponent(q)}`)
                .then(r=>r.json())
                .then(res=>renderResults(list,res.data||[]));

        },250);

    });
}

/* ========================================================= */

return { mount, unmount, loadThread };

},
{
requires:['callbora','permissions','face','navigation'],
activateOn:(route)=>route.startsWith('portal/inbox')
});