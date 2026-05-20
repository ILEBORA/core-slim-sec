__BORA_REGISTER_PLUGIN__(
'people.ui.interactions',

async function (scope) {

    const popup = await scope.getPlugin('popup');
    const uiStack = await scope.getService('uiStack');
    const callbora = await scope.getService('callbora');
    const navigation = await scope.getService('navigation');

    let initialized = false;
    let originalHTML = '';
    let currentIndex = -1; // for keyboard nav

    function applyPeopleFilters() {

        const query  = $('[data-people-search]').val().toLowerCase();
        const filter = $('.people-filters .active').data('type');
        
        $('.person-card').each(function () {
            const name = $(this).find('.name').text().toLowerCase();
            const type = $(this).attr('data-type');
            const fav  = $(this).attr('data-favorite');

            if (!type && filter !== 'all') {
                $(this).show(); // or skip filtering
                return;
            }

            const matchSearch = name.includes(query);

            const matchFilter =
                filter === 'all' ||
                (filter === 'members' && type === 'members') ||
                (filter === 'non-users' && type === 'non-users') ||
                (filter === 'favorites' && fav == 1);

            $(this).toggle(matchSearch && matchFilter);

            
        });
    }


    function debounce(fn, delay = 300) {
        let t;
        return function (...args) {
            clearTimeout(t);
            t = setTimeout(() => fn.apply(this, args), delay);
        };
    }

    const debouncedSearch = debounce(async function () {

        const query = $('[data-people-search]').val().trim();

        if (!query.length) {
            const container = document.querySelector('.people-grid');
            if (container && originalHTML) {
                container.innerHTML = originalHTML;
            }

            currentIndex = -1;
            return;
        }

        if (query.length < 2) {
            applyPeopleFilters();
            return;
        }

        const api = await scope.getService('callbora');

        const html = await api.get(
            `api/modules/people/search?q=${encodeURIComponent(query)}`
        );

        const container = document.querySelector('.people-grid');

        if (container) {
            container.innerHTML = html;container.innerHTML = html;
            applyPeopleFilters(); // required to re-apply filters on new content
        }

    }, 300);

    function highlightItem(items) {

        items.removeClass('active');

        if (currentIndex >= 0) {
            const el = items.eq(currentIndex);

            el.addClass('active');

            // scroll into view
            el[0].scrollIntoView({
                block: 'nearest'
            });
        }
    }

    function openPersonEdit(personId){
        popup.open({
            mode:'form',
            module:'people',
            group:'person',
            tab: 'edit',
            view:'edit',
            id:personId,
            size:'md'
        });
    }

    return {
        async init() {

            // prevent duplicate bindings
            if (initialized) return;
            initialized = true;

            const grid = document.querySelector('.people-grid');

            if (grid && !originalHTML) {
                originalHTML = grid.innerHTML;
            }

            const uiActions = await scope.getService('ui.actions');

            /* ========================================
             * ACTIONS (data-action based)
             * ====================================== */

            uiActions.register('people:open', async (el) => {
                const personId = $(el).data('person');

                scope.emit('people.person.open', {
                    personId
                });
            });

            uiActions.register('people:back', () => {
                scope.emit('people.back');
            });

            uiActions.register('people:follow', (el) => {
                const personId = $(el).data('person');
                const isFollowing = $(el).text().trim() === 'Following';

                scope.emit('people.follow.toggle', {
                    personId,
                    isFollowing
                });
            });

            uiActions.register('person:link.invite', (el) => {
                alertBora.alert('Person Invite feature is disabled!');
            });

            uiActions.register('person:edit', (el) => {
                // alertBora.alert('Person Edit feature is disabled!');
                const personId = $(el).data('id');
                openPersonEdit(personId);
            });

            uiActions.register('act-favorite-toggle', (el) => {
                const btn = $(el);
                const id = btn.data('id');

                callbora.post('api/modules/people/favourites/toggle', {
                    entity_id: id,
                    entity_type: 'person'
                }).then(res => {

                    if (!res.success) return;

                    const card = btn.closest('.person-card');

                    const isFav = res.data;

                    card.attr('data-favorite', isFav ? 1 : 0);

                    btn.toggleClass('is-fav', isFav);

                    applyPeopleFilters();
                });

                return;
            });

            /* ========================================
             * DELEGATED EVENTS (DOM-safe)
             * ====================================== */

            // CLICK PERSON CARD
            // $(document).on('click.people', '.person-card', function () {
            //     const personId = $(this).data('person');

            //     scope.emit('people.person.open', {
            //         personId
            //     });
            // });

            // FOLLOW BUTTON
            $(document).on('click.people', '.btn-follow', function (e) {
                e.stopPropagation();

                const personId = $(this).data('person'); // ✅ FIXED

                const isFollowing = $(this).text().trim() === 'Following';

                scope.emit('people.follow.toggle', {
                    personId,
                    isFollowing
                });
            });

            // TABS (🔥 THIS FIXES YOUR ISSUE COMPLETELY)
            $(document).on('click.people', '.person-tabs button', function () {
                const tab = $(this).data('tab');

                const root = $(this).closest('.person-view');
                const personId = root.data('person');

                scope.emit('people.tab.changed', {
                    tab,
                    personId,
                    root: root[0]
                });
            });

            // BACK BUTTON
            $(document).on('click.people', '.back-btn', function () {
                scope.emit('people.back');
            });

            // search
            $(document).on('input.people', '[data-people-search]', debouncedSearch);// applyPeopleFilters);

            // filter
            $(document).on('click.people', '.people-filters button', function () {

                $(this).addClass('active')
                    .siblings()
                    .removeClass('active');

                 const container = document.querySelector('.people-grid');

                if (container && originalHTML) {
                    container.innerHTML = originalHTML;
                }

                applyPeopleFilters();
            });

            $(document).on('keydown.people', '[data-people-search]', function (e) {

                const items = $('.person-card:visible');

                if (!items.length) return;

                // DOWN
                if (e.key === 'ArrowDown') {
                    e.preventDefault();

                    currentIndex = Math.min(currentIndex + 1, items.length - 1);

                    highlightItem(items);
                }

                // UP
                if (e.key === 'ArrowUp') {
                    e.preventDefault();

                    currentIndex = Math.max(currentIndex - 1, 0);

                    highlightItem(items);
                }

                // ENTER
                if (e.key === 'Enter') {
                    e.preventDefault();

                    const selected = items.eq(currentIndex);

                    if (selected.length) {
                        selected.click();
                    }
                }
            });

            // data-tree-select
            $(document).on('change', '[data-tree-select]', function () {

                const treeId = $(this).val();

                if (!treeId) return;

                const root = $(this).closest('.person-view');
                const personId = root.data('person');

                scope.emit('people.tree.selected', {
                    personId,
                    treeId: parseInt(treeId, 10)
                });

            });

            uiActions.register('tree:open-full', async (el) => {

                return alertBora.alert('Tree feature is disabled!');

                const root = $(el).closest('.person-view');
                const personId = root.data('person');

                const select = root.find('[data-tree-select]');
                const treeId = select.val();

                if (!treeId) return;

                const nav = await scope.getService('navigation');

                nav.go(`portal/tree/show/${treeId}`);

            });

            uiActions.register('person.view', (el)=>{
                let personId = $(el).data('id');
                
                const root = $(el).closest('.person-view');

                scope.emit('people.tab.changed', {
                    tab:"profile",
                    personId:personId,
                    root: root[0]
                });
            });

            uiActions.register('person.edit', (el)=>{
                let personId = $(el).data('id');
                openPersonEdit(personId);

                // popup.open({
                //     mode:'form',
                //     module:'people',
                //     group:'person',
                //     tab: 'edit',
                //     view:'edit',
                //     id:personId,
                //     size:'md'
                // });
            });

            uiActions.register('person.connections', (el)=>{
                let personId = $(el).data('id');
                const root = $(el).closest('.person-view');

                scope.emit('people.tab.changed', {
                    tab:"connections",
                    personId:personId,
                    root: root[0]
                });
            });

            //
            uiActions.register('people:message', async (el) => {
                const userId = $(el).data('id');
                let selectedParticipants = [];

                callbora
                    .post(
                        'api/modules/inbox/create-direct',
                        {
                            participants: [{
                                id: userId,
                                type: 'user'
                            }]
                        }
                    )
                    .then(res=>{

                        if(!res.success) return;

                        close();

                        navigation.go(
                            `portal/inbox/thread/${res.thread.id}`
                        );

                    });
            });

            uiActions.register('person.delete', (el)=>{
                let personId = $(el).data('id');

                alertBora.prompt(
                    '<h3>Confirm Action</h3>Enter your password to continue',
                    {
                        html: true,
                        prompt: '<input type="password" name="password" placeholder="Password">'
                    }
                ).then(function(det){

                    let password = btoa(det.password);

                    callbora.post(`api/modules/people/person/${personId}/delete`, {
                        password: password
                    }).then(function(response){
                        if(response.success){
                            alertBora.success('Person soft deleted');

                            //remove item
                            $('.person-card[data-person="'+personId+'"]').addClass('deleted');
                            
                            scope.emit('people.back');

                        } else {
                            alertBora.error(response.message || 'Failed');
                        }

                    });

                }); 

            });

            uiActions.register('person.restore', (el)=>{
                let personId = $(el).data('id');

                alertBora.prompt(
                    '<h3>Confirm Action</h3>Enter your password to continue',
                    {
                        html: true,
                        prompt: '<input type="password" name="password" placeholder="Password">'
                    }
                ).then(function(det){

                    let password = btoa(det.password);

                    callbora.post(`api/modules/people/person/${personId}/restore`, {
                        password: password
                    }).then(function(response){

                        if(response.success){
                            alertBora.success('Person eestore');

                            //Restore item
                            $('.person-card[data-person="'+personId+'"]').removeClass('deleted');

                            if(response.redirect){
                               navigation.go(response.redirect);
                            }
                            
                        } else {
                            alertBora.error(response.message || 'Failed');
                        }

                    });

                }); 

            });

            uiActions.register('person.force-delete', (el)=>{
                let personId = $(el).data('id');

                alertBora.prompt(
                    '<h3>Confirm Action</h3>Enter your password to continue',
                    {
                        html: true,
                        prompt: '<input type="password" name="password" placeholder="Password">'
                    }
                ).then(function(det){

                    let password = btoa(det.password);

                    callbora.post(`api/modules/people/person/${personId}/forcedelete`, {
                        password: password
                    }).then(function(response){

                        if(response.success){
                            alertBora.success('Person deleted');

                            //remove item
                            $('.person-card[data-person="'+personId+'"]').remove();

                            scope.emit('people.back');
                        } else {
                            alertBora.error(response.message || 'Failed');
                        }

                    });

                }); 

            });

            scope.on('people.view.list',function(){
                // alert('list view');
                $('.thread_context_menu').hide();
                $('.thread-info').addClass('is-hidden');

                $('.thread-info').addClass('is-hidden');
                // $('.thread-view .composer').addClass('is-hidden');
                
            });

            scope.on('people.view.thread',function(){
                // alert('thread view');
                $('.thread_context_menu').show();
                $('.thread-info').removeClass('is-hidden'); 

                // $('.thread-view .composer').removeClass('is-hidden');
            });


            scope.on('people.person.new', function(){
            
                popup.open({
                    mode:'form',
                    module:'people',
                    group:'person',
                    view:'add',
                    size:'md'
                });

            });

            formJourney.registerJourney('page.add', function ($form, done) {
                const url = $form.attr('action');
                const method = $form.attr('method') || 'POST';

                const formData = new FormData($form[0]);
                const btn = $form.find('button[type=submit]');
                const btnPrev = btn.html();
                btn.html('Processing...');

                new CallBora(url)
                    .setMethod(method)
                    .setParams(formData) // ✅ KEEP AS FORMDATA
                    .setCallback((resp) => {

                        if (resp.success) {
                            alertBora.notify('Person saved successfully', 'success', 4);

                            if (resp.redirect) {
                                appUI.content.loadPage(resp.redirect);
                            }

                            if (resp.esc) {
                                uiStack.closeTop();
                            }

                            window.location.reload();
                        } else {
                            alertBora.notify(resp.error || 'Action failed', 'error', 5);
                        }

                        done?.(resp);
                    })
                    .setError((xhr) => {
                        console.error('System error', xhr);
                        alertBora.notify('System error. Please try again later.', 'error', 15);
                        done?.(xhr);
                    })
                    .build();
            });
        }
    };
},{
    requires:['realtime'],
    activateOn: (route) => route.startsWith('portal/people')
});