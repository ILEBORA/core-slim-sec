__BORA_REGISTER_PLUGIN__(
'inbox.ui.interactions',

async function (scope) {

    // 🔧 Resolve services FIRST
    const callbora      = await scope.getService('callbora');
    const navigation    = await scope.getService('navigation');
    const state         = await scope.getService('state');
    const uiActions     = await scope.getService('ui.actions');
    const popup = await scope.getPlugin('popup');
    

    let searchInput;
    let unreadBtn;
    let list;

    function init(){
        searchInput = document.querySelector('.thread-search input');
        unreadBtn   = document.querySelector('.filter-unread');
        list        = document.querySelector('.thread-list');

        if (!searchInput || !unreadBtn || !list) return;

        searchInput.addEventListener('input', applyFilters);

        unreadBtn.addEventListener('click', () => {
            const active =
                unreadBtn.getAttribute('aria-pressed') === 'true';

            unreadBtn.setAttribute(
                'aria-pressed',
                (!active).toString()
            );

            applyFilters();
        });

        
        document.querySelectorAll('.thread-filters button')
            .forEach(btn => {
                btn.addEventListener('click', () => {
                    document
                        .querySelector('.thread-filters .active')
                        ?.classList.remove('active');

                    btn.classList.add('active');
                    applyFilters();
                });
            });

        document.addEventListener('keydown', e => {
            if (!['ArrowUp', 'ArrowDown', 'Enter'].includes(e.key)) return;

            const items = visibleItems();
            if (!items.length) return;

            let index = items.findIndex(i =>
                i.classList.contains('selected')
            );

            if (e.key === 'ArrowDown') {
                index = Math.min(index + 1, items.length - 1);
            }

            if (e.key === 'ArrowUp') {
                index = Math.max(index - 1, 0);
            }

            if (e.key === 'Enter' && index >= 0) {
                items[index].click();
                return;
            }

            items.forEach(i => i.classList.remove('selected'));
            items[index]?.classList.add('selected');
            items[index]?.scrollIntoView({ block: 'nearest' });
        });

        document.addEventListener('submit', function (e) {
            e.preventDefault();

            const form = e.target.closest('.composer');
            if (!form) return;

            const input = form.querySelector('input[name="body"]');
            const body = input.value.trim();
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
                console.log('RESPONSE:: ',res);
                scope.emit('inbox.message.sent',{
                    res
                });
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

        scope.on('inbox.view.list',function(){
            $('.thread_context_menu').hide();
            $('.thread-info').addClass('is-hidden');

            $('.thread-info').addClass('is-hidden');
            $('.thread-view .composer').addClass('is-hidden');
            
        });

        scope.on('inbox.view.thread',function(){
            $('.thread_context_menu').show();
            $('.thread-info').removeClass('is-hidden'); 

            $('.thread-view .composer').removeClass('is-hidden');
        });

        // let $scope = scope;
        scope.on('thread.participants.updated',(e) => {
            console.log('Participants updated: ' + e.count);
            state.set('thread.participants', e.count);
        });

        setupActions();

    }

    function setupActions(){
        uiActions.register('thread.participants', async (el) => {
            popup.openPopupSmart({
                key: 'thread',
                id: el.dataset.id,
                tab: 'participants',
                factory: threadPopupFactory
            });
        });

        uiActions.register('thread.details', async (el) => {
            popup.openPopupSmart({
                key: 'thread',
                id: el.dataset.id,
                tab: 'overview',
                factory: threadPopupFactory
            });
        });

        uiActions.register('thread.invite', async (el) => {
            popup.open({
                tabs: [
                    {
                        id: 'add',
                        label: 'Add Participants',
                        url: `api/modules/inbox/thread/${el.dataset.id}/addparticipants`
                    }
                ],
                activeTab: 'add'
            });
        });

        uiActions.register('inbox:view_profile', (el) => {
            let userId = $(el).data('id');
            let senderType = $(el).data('type');

            if(senderType == 'bot'){
                alertBora.alert('Bot info'); 
                return;
            }

            if (!userId) return;

            callbora
                .post('api/modules/people/resolve-by-user', {
                    user_id: userId
                })
                .then(res => {

                    if (!res.success) return;

                    navigation.go(
                        `portal/people/person/${res.person_id}/view`
                    );
                });
        });
    }

    function visibleItems() {
        return [...list.querySelectorAll('.thread-item')]
            .filter(i => i.style.display !== 'none');
    }

    function applyFilters() {
        const q = searchInput.value.trim().toLowerCase();
        const unreadOnly = unreadBtn.getAttribute('aria-pressed') === 'true';
        

        list.querySelectorAll('.thread-item').forEach(item => {
            const title   = item.querySelector('.title')?.textContent ?? '';
            const preview = item.querySelector('.preview')?.textContent ?? '';
            const unread  = item.classList.contains('unread');

            const matchesText =
                (title + ' ' + preview).toLowerCase().includes(q);

            const matchesUnread =
                !unreadOnly || unread;

            const activeType =
                document.querySelector('.thread-filters .active')
                    ?.dataset.type ?? 'all';

            const matchesType =
                activeType === 'all' ||
                item.dataset.type === activeType;

            //item.style.display =
            //  matchesText && matchesUnread ? '' : 'none';

            item.style.display =
                matchesText && matchesUnread && matchesType ? '' : 'none';
        });
    }

    //Popups
    function threadPopupFactory(threadId){
        return {
            tabs: [
                {
                    id: 'overview',
                    label: 'Overview',
                    url: `api/modules/inbox/thread/${threadId}/info`
                },
                {
                    id: 'participants',
                    label: 'Participants',
                    url: `api/modules/inbox/thread/${threadId}/participants`
                },
                {
                    id: 'settings',
                    label: 'Settings',
                    url: `api/modules/inbox/thread/${threadId}/settings`
                }
            ]
        };
    }

    return {
        init,
        applyFilters
    };

});