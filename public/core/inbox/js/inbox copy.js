__BORA_REGISTER_PLUGIN__(
'Inbox',
function(scope){

    const hooks      = scope.getService('hooks');
    const callbora   = scope.getService('callbora');
    const navigation = scope.getService('navigation');
    const appInboxComposer = scope.getPlugin('InboxComposer');

    let threadId = null;
    let mounted  = false;
    let mainUserId = rd('uID') ?? window.MAIN_USER_ID ?? null;

    /* ==========================================
       LIFECYCLE
    ========================================== */

    function mount(){
        // alert('Here mount inbox...');
        if (mounted) return;
        mounted = true;

        bindUI();

        resolveThreadFromRoute();

        // self.threadId = $('.thread-view').data('thread');
        // alert(threadId);

        // hooks.add('realtime:*', handleRealtimeWildcard);
        // registerHooks();

        console.log('[Inbox] mounted');
    }

    function unmount(){

        if (!mounted) return;
        mounted = false;

        $(document).off('.inbox');

        // hooks.remove('realtime:*', handleRealtimeWildcard);

        threadId = null;

        console.log('[Inbox] unmounted');
    }

    //
    function registerHooks() {
    //     scope.on(
    //         'realtime:inbox:thread:' + threadId,
    //         handleRealtime.bind(this) // 👈 CRITICA//e => this.handleRealtime(e)
    //     );

        initInboxRealtime();
    }

    function initInboxRealtime() { 
        const userId = mainUserId;// window.MAIN_USER_ID;
        // alert('here '+rd('uID'));
        if(!userId) return;
        
        scope.on('realtime:inbox:user:' + userId, e => {
            console.log('[Inbox realtime user event]', e);
            const data = e.payload;
            if (data.type !== 'thread.bumped') return;

            const { thread_id, preview, time } = data;
            // alert(thread_id);
            let item = document.querySelector(
                `.thread-item[data-thread="${thread_id}"]`
            );

            const inboxCont = $('.inbox-layout');
            if(inboxCont.length){ // If within the inbox view
                //If thread does not exist create it
                if (!item) {
                    item = createThreadItem({
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
                        
                // if(soundOn){
                    // Play sound
                    // var audio = new Audio('assets/sound/doink.mp3');
                    // audio.play();
                // }
                
                //Finally
                // Optional global app badge
                //appUI.notifications.increment('inbox');
            }
        });
    }

    function createThreadItem({ thread_id, preview, time }) {
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

        const url = normalizeUrl(window.location); //alert(url);
        const match = url.match(/\portal\/inbox\/show\/(\d+)/);

        if (!match) {
            setView('list');
            return;
        }

        threadId = match[1];
        setView('thread');
        // alert('thread:: '+threadId);
        loadThread(threadId);
    }

    function openThread(id){

        if (!id) return;

        // navigation.go(`portal/inbox/show/${id}`);
    }

    /* ---------------------------------
        | Utilities
        |---------------------------------*/

    function escape(text) {
        const div = document.createElement('div');
        div.textContent = text ?? '';
        return div.innerHTML;
    }

    function focus(){
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

    }

    /* ==========================================
       THREAD LOADING
    ========================================== */

    function loadThread(id){
        const container = document.querySelector('.messages');
        if (!container) return;
        //alert('Start thread');
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
                        msg.html
                    );
                });

                if(!res.data.has_more){
                    $('.load-history').hide();
                }else{
                    $('.load-history').show();
                }

                scrollBottom();
                bindThread(id, res);

                subscribeThreadRealtime(id);

            })
            .setDone(() =>{
                history.pushState({}, '', `portal/inbox/show/${id}`);
                bindScroll();
            })
            .setError((xhr) => {
                console.error("Error:", xhr);
                container.innerHTML = "<p style='color:red'>Failed to load.</p>";
            })
            .build();
    }

    function bindThread(threadId, res){
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

    }

    let threadHook = null;

    function subscribeThreadRealtime(id){
        console.log('Thread Id ', id);
        if(threadHook){
            scope.off(threadHook, handleRealtime);
        }

        threadHook = 'realtime:inbox:thread:' + id;

        scope.on(threadHook, handleRealtime);

        console.log('[Inbox] subscribed', threadHook);
    }

    function markThreadRead(threadId) {
        const item = document.querySelector(
            `.thread-item[data-thread="${threadId}"]`
        );
        if (!item) return;

        item.classList.remove('unread');
        item.querySelector('.badge')?.remove();
    }

    // Infinity
    function getOldestMessageId(){

        const first = document.querySelector('.message');

        return first?.dataset.messageId || null;
    }

    let loading = false;
    
    function loadPreviousMessages(){
        
        const beforeId = getOldestMessageId();
        console.log('load previous:: ' + getOldestMessageId());
        if(!beforeId) return;

        if(loading) return;

        loading = true;

        new CallBora(`api/modules/inbox/view-thread/${threadId}`)
            .setMethod("GET")
            .setParams({
                before: beforeId
            })
            .setCallback(res => {

                if(!res.success) return;

                prependMessages(res.data.messages);

                if(!res.data.has_more){
                    $('.load-history').hide();
                }else{
                    $('.load-history').show();
                }

                loading = false;

            })
            .build();
    }

    function prependMessages(items){

        const container = document.querySelector('.messages');
        const scrollBox = document.querySelector('.messages-cont');

        const prevHeight = scrollBox.scrollHeight;

        items.forEach(item => {
            container.insertAdjacentHTML('afterbegin', item.html);
        });

        const newHeight = scrollBox.scrollHeight;

        scrollBox.scrollTop += (newHeight - prevHeight);
    }

    /* ==========================================
       UI BINDING
    ========================================== */

    function bindUI(){
        //alert('inbox');
        // document.addEventListener('click', handleClick);
        // document.addEventListener('keydown', handleKeyNav);
        bindSearch();

        // $(function(){
        //     $('.inbox-layout').find('.fab-new-thread').click(function(){
        //         alert('here');
        //         openNewThread();
        //         // return;
        //     });
        // });

        $(document)

            .off('.inbox') // prevent duplicates

            .on('click.inbox', '.thread-item', handleThreadClick)

            .on('click.inbox', '.back-btn', handleBack)

            .on('click.inbox', '.fab-new-thread', openNewThread)

            .on('keydown.inbox', handleKeyNav);

    }

    function handleThreadClick(e){
        const id = $(this).data('thread');
        if(!id) return;

        highlightThread(this);
        setView('thread');
        loadThread(id);
    }

    function handleBack(){
        setView('list');
        history.pushState({}, '', 'portal/inbox');
    }

    function bindScroll() {
        const container = document.querySelector('.messages-cont');

        container.addEventListener('scroll', () => {
            console.log(container.scrollTop);
            if (container.scrollTop < 50) {
                loadPreviousMessages();
            }
        });
    }
    
    function bindSearch(){

        const el = document.querySelector('.inbox-composer');
        if (!el || el.dataset.bound) return;

        el.dataset.bound = '1';

        const input = el.querySelector('.participant-search');
        const list  = el.querySelector('.participant-results');

        let timer;

        input.addEventListener('input', () => {

            clearTimeout(timer);

            const q = input.value.trim();

            if (q.length < 2){
                list.innerHTML = '';
                return;
            }

            timer = setTimeout(() => {

                fetch(`api/modules/inbox/participants?q=${encodeURIComponent(q)}`)
                    .then(r => r.json())
                    .then(res => renderResults(list, res.data || []));

            }, 250);

        });

    }

    function bindSearchO() {
        this.el = document.querySelector('.inbox-composer');
        if (!this.el) return;
        
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
    }

    function handleClick(e){

        const threadItem = e.target.closest('.thread-item');
        console.log(threadItem);
        if (threadItem){

            const id = threadItem.dataset.thread;
            if (!id) return;

            highlightThread(threadItem);
            setView('thread');
            loadThread(id);
            return;
        }

        const backBtn = e.target.closest('.back-btn');
        if (backBtn){
            setView('list');
            history.pushState({}, '', 'portal/inbox');
            return;
        }

        const startBtn = e.target.closest('[data-action="inbox:start"]');
        if (startBtn){
            //startConversation();
            return;
        }

        // const fab = e.target.closest('.fab-new-thread');
        // if (fab){
        //     // startConversation();
        //     openNewThread();
        //     return;
        // }
    }

    function openNewThread(){
        appInboxComposer.mount();
        appInboxComposer.open();
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
    function handleRealtime(e) {
        if (!e || !e.channel) return;
        
        const data = e.payload;

        console.log('HANDLER FOR:: ',data);

        if(data){
            switch (data.type) {
                case 'message.sent':
                    // alert(this.mainUse  rId);
                    console.log('message.sent called by '+ data.sender_id +' from ' + mainUserId);
                    appendMessage(data, {
                        isMe: data.sender_id === mainUserId
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
    }

    // function handleRealtimeWildcard(eventName, e){

    //     if (!mounted) return;
    //     if (!eventName.startsWith('realtime:inbox:')) return;

    //     if (eventName === `realtime:inbox:thread:${threadId}`){
    //         appendMessage(e);
    //     }

    //     /* Status update */
    //     if (eventName === 'realtime:inbox:status'){
    //         updateMessageStatus(e);
    //         return;
    //     }
    // }

    /* ---------------------------------
        | Typing indicator
        |---------------------------------*/

    function showTyping() {
        document.querySelector('.typing-indicator')?.removeAttribute('hidden');
    }

    function hideTyping() {
        document.querySelector('.typing-indicator')?.setAttribute('hidden', true);
    }

    function appendMessage(msg){
        console.log('appendMessage:: ', msg);
        const container = document.querySelector('.messages');
        if (!container) return;

        container.insertAdjacentHTML(
            'beforeend',
            msg.html
        );

        scrollBottom();
    }

    function scrollBottom(){
        const c = document.querySelector('.messages-cont');
        if (c) c.scrollTop = c.scrollHeight + 40;
    }

    /* ==========================================
    MESSAGE STATUS UPDATE
    ========================================== */

    function updateMessageStatus(payload){

        if (!payload?.message_id) return;

        const el = document.querySelector(
            `[data-message-id="${payload.message_id}"]`
        );

        if (!el) return;

        if (payload.read_at){
            el.dataset.status = 'read';
            return;
        }

        if (payload.delivered_at){
            el.dataset.status = 'delivered';
        }
    }

    /* ==========================================
       START CONVERSATION
    ========================================== */

    function startConversation(){

        fetch('api/modules/inbox/create-thread', {
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
                setView('thread');
                loadThread(res.data.thread.id);
            }
        });
    }

    function escape(text){
        const div = document.createElement('div');
        div.textContent = text ?? '';
        return div.innerHTML;
    }

    return { mount, unmount, loadThread };

},
{
    requires:['hooks','callbora','permissions','face','navigation'],
    activateOn: (route) => route.startsWith('portal/inbox'),
    // permission: { group:'inbox', sub:'view' }
});