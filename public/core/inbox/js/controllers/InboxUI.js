class InboxUI {

    constructor(scope){

        this.scope = scope;

        this.cache = {};

        this.refreshCache();

        this.threadId = null;

        //
        this.bound = false;

        // bind handlers once
        this.handleThreadClick = this.handleThreadClick.bind(this);
        this.handleBack = this.handleBack.bind(this);
        this.handleKeyNav = this.handleKeyNav.bind(this);
        this.handleNewThread = this.handleNewThread.bind(this);

        //
        this.loading = false;
    }

    bind(){

        if(this.bound) return;
        this.bound = true;

        $(document)
            .on('click.inbox','.thread-item',this.handleThreadClick)
            .on('click.inbox','.back-btn',this.handleBack)
            .on('click.inbox','.fab-new-thread',this.handleNewThread)
            .on('keydown.inbox',this.handleKeyNav);

        console.log('[InboxUI] bound');

        this.bindThreadSearch();
    }

    unbind(){

        if(!this.bound) return;

        $(document).off('.inbox');

        this.bound = false;

        console.log('[InboxUI] unbound');
    }

    refreshCache(){

        this.cache.layout         = document.querySelector('.inbox-layout');
        this.cache.threadList     = document.querySelector('.thread-list');
        this.cache.messages       = document.querySelector('.messages');
        this.cache.messagesCont   = document.querySelector('.messages-cont');
        this.cache.typing         = document.querySelector('.typing-indicator');
    }

    /* =========================
       THREADS
    ========================= */

    getThreadItem(id){

        return document.querySelector(
            `.thread-item[data-thread="${id}"]`
        );
    }

    createThreadItem(data){

        const list = this.cache.threadList;

        if(!list) return;

        const li = document.createElement('li');

        li.className = 'thread-item unread';
        li.dataset.thread = data.thread_id;

        li.innerHTML = `
            <div class="avatar">
                <span class="status-dot online"></span>
            </div>

            <div class="meta">
                <div class="title">Conversation...</div>
                <div class="preview">${data.preview ?? ''}</div>
            </div>

            <div class="stats">
                <span class="badge">1</span>
                <time>${data.time ?? ''}</time>
            </div>
        `;

        list.prepend(li);

        return li;
    }

    setThreadSelected(threadId){

        document
            .querySelectorAll('.thread-item')
            .forEach(el => el.classList.remove('selected'));

        const item = this.getThreadItem(threadId);

        if(item){
            item.classList.add('selected');
        }

        this.setActiveThread(threadId);
    }

    bumpThread(threadId){

        const item = this.getThreadItem(threadId);
        const list = document.querySelector('.thread-list');

        if(!item || !list) return;

        if(list.firstElementChild === item){
            return;
        }

        // First position
        const first = item.getBoundingClientRect();

        // Move element
        list.prepend(item);

        // Last position
        const last = item.getBoundingClientRect();

        const deltaY = first.top - last.top;

        // Invert
        item.style.transform = `translateY(${deltaY}px)`;

        // Force reflow
        item.offsetHeight;

        // Play animation
        item.style.transition = 'transform 220ms ease';

        item.style.transform = '';

        item.addEventListener('transitionend', () => {
            item.style.transition = '';
        }, {once:true});

        // highlight
        item.classList.add('bumped');

        setTimeout(()=>{
            item.classList.remove('bumped');
        },600);
        
    }

    incrementThreadBadge(threadId){

        const item = this.getThreadItem(threadId);

        if(!item) return;

        let badge = item.querySelector('.badge');

        if(!badge){

            badge = document.createElement('span');

            badge.className = 'badge';
            badge.textContent = '1';

            item.querySelector('.stats')?.prepend(badge);

        }
        else{

            badge.textContent =
                parseInt(badge.textContent, 10) + 1;

        }

    }

    clearThreadBadge(threadId){

        const item = this.getThreadItem(threadId);

        if(!item) return;

        item.querySelector('.badge')?.remove();

    }

    /* =========================
       MESSAGES
    ========================= */

    appendMessage(msg){

        if(document.querySelector(
            `[data-message-id="${msg.id}"]`
        )){
            return;
        }

        this.cache.messages
            ?.insertAdjacentHTML('beforeend', msg.html);

        this.scrollBottom();
    }

    scrollBottom(){

        const c = this.cache.messagesCont;

        if(c){
            c.scrollTop = c.scrollHeight + 40;
        }
        
    }

    bindScroll() {
        const container = document.querySelector('.messages-cont');

        container.addEventListener('scroll', () => {
            console.log(container.scrollTop);
            if (container.scrollTop < 50) {
                this.loadPreviousMessages();
            }
        });
    }

    // Infinity
    getOldestMessageId(){

        const first = document.querySelector('.message');

        return first?.dataset.messageId || null;
    }
    
    loadPreviousMessages(){
        
        const beforeId = this.getOldestMessageId();
        console.log('load previous:: ' + this.getOldestMessageId());
        if(!beforeId) return;

        if(loading) return;

        this.loading = true;

        new CallBora(`api/modules/inbox/view-thread/${threadId}`)
            .setMethod("GET")
            .setParams({
                before: beforeId
            })
            .setCallback(res => {

                if(!res.success) return;

                this.prependMessages(res.data.messages);

                if(!res.data.has_more){
                    $('.load-history').hide();
                }else{
                    $('.load-history').show();
                }

                this.loading = false;

            })
            .build();
    }

    prependMessages(items){

        const container = document.querySelector('.messages');
        const scrollBox = document.querySelector('.messages-cont');

        const prevHeight = scrollBox.scrollHeight;

        items.forEach(item => {
            container.insertAdjacentHTML('afterbegin', item.html);
        });

        const newHeight = scrollBox.scrollHeight;

        scrollBox.scrollTop += (newHeight - prevHeight);
    }

    /* =========================
       TYPING
    ========================= */

    showTyping(){

        this.cache.typing
            ?.removeAttribute('hidden');
    }

    hideTyping(){

        this.cache.typing
            ?.setAttribute('hidden', true);
    }

    /* =========================
       VIEW
    ========================= */

    setView(view){
       this.cache.layout = document.querySelector('.inbox-layout');
        this.cache.layout
            ?.setAttribute('data-view', view);
    }

    //
    updateThreadPreview(item, preview){

        if(!item) return;

        const el = item.querySelector('.preview');

        if(el){
            el.textContent = preview ?? '';
        }
    }

    updateThreadTime(item, time){

        if(!item) return;

        const el = item.querySelector('time');

        if(el){
            el.textContent = time ?? '';
        }
    }

    //
    setActiveThread(threadId){
        this.threadId = threadId;
    }
    getActiveThread(){
        return this.threadId;
    }

    //
    /* =========================
       UI EVENTS
    ========================= */

    handleThreadClick(e){

        const id = $(e.currentTarget).data('thread');
        if(!id) return;

        this.setThreadSelected(id);

        this.scope.emit('inbox.thread.open', {threadId:id});
    }

    handleBack(){

        this.setView('list');

        // this.navigation.go('portal/inbox');
        history.pushState({},'',`portal/inbox`);
    }

    handleNewThread(){

        const composer = this.scope.getPlugin('InboxComposer');

        composer?.mount?.();
        composer?.open?.();
    }

    handleKeyNav(e){

        if(!['ArrowUp','ArrowDown','Enter'].includes(e.key)) return;

        const list = document.querySelector('.thread-list');
        if(!list) return;

        const items = [...list.querySelectorAll('.thread-item')];

        let index = items.findIndex(i => i.classList.contains('selected'));

        if(e.key === 'ArrowDown') index = Math.min(index+1, items.length-1);
        if(e.key === 'ArrowUp')   index = Math.max(index-1, 0);

        if(e.key === 'Enter'){
            items[index]?.click();
            return;
        }

        items.forEach(i => i.classList.remove('selected'));
        items[index]?.classList.add('selected');
    }

    // Search
    bindThreadSearch(){

        const input = document.querySelector('.thread-search input');
        if(!input) return;

        input.addEventListener('input', e=>{

            const q = e.target.value.toLowerCase();

            document
                .querySelectorAll('.thread-item')
                .forEach(item=>{

                    const text = item.textContent.toLowerCase();

                    item.style.display =
                        text.includes(q) ? '' : 'none';

                });

        });

    }
    

    searchParticipants(query){
        callbora
            .get(`api/modules/inbox/participants?q=${encodeURIComponent(query)}`)
            .then(res=>{
                this.renderParticipants(res.data);
            });

    }

}