class PeopleUI {

    constructor(scope) {
        this.scope = scope;

        this.cache = {};

        this.refreshCache();

        this.personId = null;

        //
        this.bound = false;

        // bind handlers once
        this.handleThreadClick = this.handleThreadClick.bind(this);
        this.handleBack = this.handleBack.bind(this);
        this.handleKeyNav = this.handleKeyNav.bind(this);
        this.handleNewThread = this.handleNewThread.bind(this);

        //
        this.loading = false;

        this.lastSound = 0;


        this.cache = {
            container: null, // people grid (list)
            detail: null     // right panel
        };
    }

    /* ========================================
     * BIND / UNBIND
     * ====================================== */

    async bind() {
        if(this.bound) return;
        this.bound = true;

        this.refreshCache(); //safe

        $(document)
            .on('click.people','.person-card',this.handleThreadClick)
            .on('click.people','.back-btn',this.handleBack)
            .on('click.people','.fab-new-thread',this.handleNewThread)
            .on('click.people','.new-thread-btn',this.handleNewThread)
            .on('keydown.people',this.handleKeyNav);

        console.log('[PeopleUI] bound');

        // this.bindThreadSearch();
        
        this.scope.on('people.person.read', ({personId}) => {

            new CallBora(`api/modules/people/person/${personId}/view`)
                .setMethod("POST")
                .setCallback(res => {
                    
                    if(!res.success) return;
                    // console.log(res);
                    // alert('need bread');
                    // Option B: wait for server push (better)
                    this.scope.emit('breadcrumbs:resolve', {
                        url:`portal/people/person/${personId}/view`, 
                        response: res
                    });
                    // alert({
                    //     url:`portal/people/person/${personId}/view`, 
                    //     response: res
                    // });
                    // Option A: optimistic UI
                    this.clearThreadBadge(personId);

                    
                })
                .build();
        });

        
        this.cache.container = document.querySelector('.people-grid');
        this.cache.detail    = document.querySelector('.thread-view');
    }

    unbind() {
        if(!this.bound) return;

        $(document).off('.people');

        this.bound = false;

        console.log('[PeopleUI] unbound');

        this.cache.container = null;
        this.cache.detail    = null;
    }

    refreshCache(){
        this.cache.layout         = document.querySelector('.inbox-layout.people');
        this.cache.threadList     = document.querySelector('.thread-list');
        this.cache.messages       = document.querySelector('.messages');
        this.cache.messagesCont   = document.querySelector('.messages-cont');
    }

    clearThreadBadge(personId){

        const item = this.getThreadItem(personId);

        if(!item) return;

        item.querySelector('.badge')?.remove();

    }

    /* =========================
       VIEW
    ========================= */
    setView(view){
        this.cache.layout = document.querySelector('.inbox-layout.people');
        this.cache.layout
            ?.setAttribute('data-view', view);

        this.refreshCache();

        //Mount 
        if(view == 'list'){
            // $('.thred_context_menu').hide();
            // $('.thread-info').hide();
            this.scope.emit('people.view.list');
        }else{
            // $('.thred_context_menu').show();
            // $('.thread-info').show();
            this.scope.emit('people.view.thread');
        } 

    }

    //
    setActiveThread(personId){
        this.personId = personId;
    }
    getActiveThread(){
        return this.personId;
    }

    //
    /* =========================
       UI EVENTS
    ========================= */

    handleThreadClick(e){
        // alert('thread clicked: ' + $(e.currentTarget).data('person'));
        const id = $(e.currentTarget).data('person');
        if(!id) return;

        this.setThreadSelected(id);

        this.scope.emit('people.person.open', {personId:id});
    }

    setThreadSelected(personId){

        document
            .querySelectorAll('.person-card')
            .forEach(el => el.classList.remove('selected'));

        const item = this.getThreadItem(personId);

        if(item){
            item.classList.add('selected');
        }

        this.setActiveThread(personId);

        this.clearThreadBadge(personId);
    }

    handleBack(){

        this.setView('list');

        // this.navigation.go('portal/inbox');
        history.pushState({},'',`portal/people`);
    }

    async handleNewThread(){
        this.scope.emit('people.person.new');
    }

    handleKeyNav(e){

        if(!['ArrowUp','ArrowDown','Enter'].includes(e.key)) return;

        const list = document.querySelector('.thread-list');
        if(!list) return;

        const items = [...list.querySelectorAll('.person-card')];

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

    getThreadItem(id){

        return document.querySelector(
            `.person-card[data-person="${id}"]`
        );
    }

    // Search
    bindThreadSearch(){

        const input = document.querySelector('.thread-search input');
        if(!input) return;

        input.addEventListener('input', e=>{

            const q = e.target.value.toLowerCase();

            document
                .querySelectorAll('.person-card')
                .forEach(item=>{

                    const text = item.textContent.toLowerCase();

                    item.style.display =
                        text.includes(q) ? '' : 'none';

                });

        });

    }

    async playMessageSound(){
        const sound = await this.scope.getService('sound');
        const now = Date.now();
        if(now - this.lastSound < 800) return; // debounce
        this.lastSound = now;
        sound.play('message');
    }

    /* ========================================
     * DIRECTORY (LIST)
     * ====================================== */

    renderListHTML(html) {
        if (!this.cache.container) return;

        this.cache.container.innerHTML = html;
    }

    /* ========================================
     * DETAIL VIEW (MAIN PANEL)
     * ====================================== */

    renderHTML(html) {
        if (!this.cache.detail) return;

        this.cache.detail    = document.querySelector('.thread-view');

        this.cache.detail.innerHTML = html;

        this.showDetailPanel();

        // 🔁 IMPORTANT: rebind dependent modules
        this.scope.emit('people.view.rendered');
    }

    clearDetail() {
        if (!this.cache.detail) return;

        this.cache.detail.innerHTML = `
            <div class="empty-state">
                Select a person
            </div>
        `;

        this.hideDetailPanel();
    }

    /* ========================================
     * TABS (SERVER-RENDERED)
     * ====================================== */

    renderTabHTML(tab, html) {
        const el = document.querySelector(
            `.tab-panel[data-tab="${tab}"]`
        );

        if (!el) return;

        el.innerHTML = html;
    }

    /* ========================================
     * STATE (VISUAL)
     * ====================================== */

    setActivePerson(personId) {
        document.querySelectorAll('.person-card')
            .forEach(el => el.classList.remove('selected'));

        const active = document.querySelector(
            `.person-card[data-person="${personId}"]`
        );

        active?.classList.add('selected');


    }

    updateFollowState(personId, isFollowing) {

        // card
        const card = document.querySelector(
            `.person-card[data-person="${personId}"]`
        );

        card?.classList.toggle('following', isFollowing);

        // detail view button
        const btn = document.querySelector(
            `.btn-follow[data-person="${personId}"]`
        );

        if (btn) {
            btn.textContent = isFollowing ? 'Following' : 'Follow';
        }
    }

    /* ========================================
     * PANEL CONTROL (MOBILE SUPPORT)
     * ====================================== */

    showDetailPanel() {
        this.cache.detail?.classList.add('active');
    }

    hideDetailPanel() {
        this.cache.detail?.classList.remove('active');
    }

    /* ========================================
     * LOADING STATES (OPTIONAL BUT IMPORTANT)
     * ====================================== */

    showLoading() {
        if (!this.cache.detail) return;

        this.cache.detail.innerHTML = `
            <div class="loading-state">
                Loading...
            </div>
        `;
    }

    showTabLoading(tab) {
        const el = document.querySelector(
            `.tab-panel[data-tab="${tab}"]`
        );

        if (!el) return;

        el.innerHTML = `
            <div class="loading-state small">
                Loading...
            </div>
        `;
    }
}