class PeopleUI {

    constructor(scope){

        this.scope = scope;

        this.personId = null;

        this.bound = false;

        this.loading = false;

        this.lastSound = 0;

        /* =====================================
         * REACTIVE DOM LOCATORS
         * =================================== */

        this.dom = {

            layout:
                scope.bindDom(
                    '.inbox-layout.people'
                ),

            grid:
                scope.bindDom(
                    '.people-grid'
                ),

            detail:
                scope.bindDom(
                    '.thread-view'
                ),

            threadList:
                scope.bindDom(
                    '.thread-list'
                ),

            messages:
                scope.bindDom(
                    '.messages'
                ),

            messagesCont:
                scope.bindDom(
                    '.messages-cont'
                )

        };

        /* =====================================
         * BIND METHODS
         * =================================== */

        this.handleThreadClick =
            this.handleThreadClick.bind(this);

        this.handleBack =
            this.handleBack.bind(this);

        this.handleKeyNav =
            this.handleKeyNav.bind(this);

        this.handleNewThread =
            this.handleNewThread.bind(this);

    }

    /* ========================================
     * BIND / UNBIND
     * ====================================== */

    async bind(){

        if(this.bound){
            return;
        }

        this.bound = true;

        $(document)

            .on(
                'click.people',
                '.person-card',
                this.handleThreadClick
            )

            .on(
                'click.people',
                '.back-btn',
                this.handleBack
            )

            .on(
                'click.people',
                '.fab-new-thread',
                this.handleNewThread
            )

            .on(
                'click.people',
                '.new-thread-btn',
                this.handleNewThread
            )

            .on(
                'keydown.people',
                this.handleKeyNav
            );

        console.log('[PeopleUI] bound');

        this.scope.on(
            'people.person.read',

            ({personId}) => {

                new CallBora(
                    `api/modules/people/person/${personId}/view`
                )

                .setMethod('POST')

                .setCallback(res => {

                    if(!res.success){
                        return;
                    }

                    this.scope.emit(
                        'breadcrumbs:resolve',
                        {
                            url:
                                `portal/people/person/${personId}/view`,

                            response: res
                        }
                    );

                    this.clearThreadBadge(
                        personId
                    );

                })

                .build();

            }
        );

    }

    unbind(){

        if(!this.bound){
            return;
        }

        $(document).off('.people');

        this.bound = false;

        console.log('[PeopleUI] unbound');

    }

    /* ========================================
     * HELPERS
     * ====================================== */

    getGrid(){
        return this.dom.grid();
    }

    getDetail(){
        return this.dom.detail();
    }

    getLayout(){
        return this.dom.layout();
    }

    getThreadList(){
        return this.dom.threadList();
    }

    /* ========================================
     * THREAD HELPERS
     * ====================================== */

    getThreadItem(personId){

        return this
            .getGrid()
            ?.find(
                `.person-card[data-person="${personId}"]`
            );

    }

    clearThreadBadge(personId){

        const $item =
            this.getThreadItem(personId);

        if(!$item?.length){
            return;
        }

        $item.find('.badge').remove();

    }

    setThreadSelected(personId){

        this.getGrid()
            ?.find('.person-card')
            .removeClass('selected');

        const $item =
            this.getThreadItem(personId);

        $item?.addClass('selected');

        this.setActiveThread(personId);

        this.clearThreadBadge(personId);

    }

    /* ========================================
     * ACTIVE PERSON
     * ====================================== */

    setActiveThread(personId){
        this.personId = personId;
    }

    getActiveThread(){
        return this.personId;
    }

    /* ========================================
     * VIEW STATE
     * ====================================== */

    setView(view){

        this.getLayout()
            ?.attr('data-view', view);

        if(view === 'list'){

            this.scope.emit(
                'people.view.list'
            );

        }else{

            this.scope.emit(
                'people.view.thread'
            );

        }

    }

    /* ========================================
     * UI EVENTS
     * ====================================== */

    handleThreadClick(e){

        const personId =
            $(e.currentTarget)
                .data('person');

        if(!personId){
            return;
        }

        this.setThreadSelected(
            personId
        );

        this.scope.emit(
            'people.person.open',
            {
                personId
            }
        );

    }

    handleBack(){

        this.setView('list');

        history.pushState(
            {},
            '',
            'portal/people'
        );

    }

    async handleNewThread(){

        this.scope.emit(
            'people.person.new'
        );

    }

    handleKeyNav(e){

        if(
            ![
                'ArrowUp',
                'ArrowDown',
                'Enter'
            ].includes(e.key)
        ){
            return;
        }

        const $list =
            this.getThreadList();

        if(!$list?.length){
            return;
        }

        const items =
            $list
                .find('.person-card')
                .toArray();

        let index =
            items.findIndex(
                el => el.classList.contains('selected')
            );

        if(e.key === 'ArrowDown'){

            index = Math.min(
                index + 1,
                items.length - 1
            );

        }

        if(e.key === 'ArrowUp'){

            index = Math.max(
                index - 1,
                0
            );

        }

        if(e.key === 'Enter'){

            items[index]?.click();

            return;

        }

        items.forEach(el => {
            el.classList.remove('selected');
        });

        items[index]
            ?.classList
            .add('selected');

    }

    /* ========================================
     * LIST RENDERING
     * ====================================== */

    renderListHTML(html){

        const $grid =
            this.getGrid();

        if(!$grid?.length){
            return;
        }

        $grid.html(html);

    }

    /* ========================================
     * DETAIL VIEW
     * ====================================== */

    renderHTML(html){

        const $detail =
            this.getDetail();

        if(!$detail?.length){
            return;
        }

        $detail.html(html);

        this.showDetailPanel();

        this.scope.emit(
            'people.view.rendered'
        );

    }

    clearDetail(){

        const $detail =
            this.getDetail();

        if(!$detail?.length){
            return;
        }

        $detail.html(`
            <div class="empty-state">
                Select a person
            </div>
        `);

        this.hideDetailPanel();

    }

    /* ========================================
     * TABS
     * ====================================== */

    renderTabHTML(tab, html){

        const $detail =
            this.getDetail();

        if(!$detail?.length){
            return;
        }

        const $panel =
            $detail.find(
                `.tab-panel[data-tab="${tab}"]`
            );

        if(!$panel.length){
            return;
        }

        $panel.html(html);

    }

    /* ========================================
     * PERSON STATE
     * ====================================== */

    setActivePerson(personId){

        this.getGrid()
            ?.find('.person-card')
            .removeClass('selected');

        this.getThreadItem(personId)
            ?.addClass('selected');

    }

    updateFollowState(
        personId,
        isFollowing
    ){

        const $card =
            this.getThreadItem(personId);

        $card?.toggleClass(
            'following',
            isFollowing
        );

        const $btn =
            this.getDetail()
                ?.find(
                    `.btn-follow[data-person="${personId}"]`
                );

        if($btn?.length){

            $btn.text(
                isFollowing
                    ? 'Following'
                    : 'Follow'
            );

        }

    }

    /* ========================================
     * PANEL CONTROL
     * ====================================== */

    showDetailPanel(){

        this.getDetail()
            ?.addClass('active');

    }

    hideDetailPanel(){

        this.getDetail()
            ?.removeClass('active');

    }

    /* ========================================
     * LOADING
     * ====================================== */

    showLoading(){

        const $detail =
            this.getDetail();

        if(!$detail?.length){
            return;
        }

        $detail.html(`
            <div class="loading-state">
                Loading...
            </div>
        `);

    }

    showTabLoading(tab){

        const $detail =
            this.getDetail();

        if(!$detail?.length){
            return;
        }

        const $panel =
            $detail.find(
                `.tab-panel[data-tab="${tab}"]`
            );

        if(!$panel.length){
            return;
        }

        $panel.html(`
            <div class="loading-state small">
                Loading...
            </div>
        `);

    }

    /* ========================================
     * SEARCH
     * ====================================== */

    bindThreadSearch(){

        const $list =
            this.getThreadList();

        if(!$list?.length){
            return;
        }

        const $input =
            $list.find(
                '.thread-search input'
            );

        if(!$input.length){
            return;
        }

        $input.on(
            'input',

            e => {

                const q =
                    e.target.value
                        .toLowerCase();

                this.getGrid()
                    ?.find('.person-card')
                    .each(function(){

                        const text =
                            this.textContent
                                .toLowerCase();

                        this.style.display =
                            text.includes(q)
                                ? ''
                                : 'none';

                    });

            }
        );

    }

    /* ========================================
     * SOUND
     * ====================================== */

    async playMessageSound(){

        const sound =
            await this.scope.getService(
                'sound'
            );

        const now = Date.now();

        if(now - this.lastSound < 800){
            return;
        }

        this.lastSound = now;

        sound.play('message');

    }

}