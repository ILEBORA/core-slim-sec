__BORA_REGISTER_PLUGIN__('inbox.composer', async function(scope){

    const callbora   = await scope.getService('callbora');
    const navigation = await scope.getService('navigation');
    const uiActions     = await scope.getService('ui.actions');

    let el;
    let selectedUser = null;
    let selectedParticipants = [];
    let bound = false;

    function init(){
        el = document.querySelector('.inbox-composer');

        if(!el || bound) return;

        bind();

        bound = true;
    }

    function bind(){

        // el.querySelector('.close')
        //     ?.addEventListener('click', close);

        const input = el.querySelector('.participant-search');
        const list  = el.querySelector('.participant-results');

        let timer;

        input?.addEventListener('input', ()=>{

            clearTimeout(timer);

            const q = input.value.trim();

            if(q.length < 2){
                list.innerHTML = '';
                preloadSuggestions();
                return;
            }

            timer = setTimeout(()=>{

                callbora
                    .get(
                        'api/modules/inbox/participants',
                        {q}
                    )
                    .then(res=>{
                        renderResults(res.data || []);
                    });

            },250);

        });

        // el.querySelector('.start-btn')
        //     ?.addEventListener('click', startConversation);

        uiActions.register('inbox:confirm-start', (el)=>{
            startConversation();
        });

        uiActions.register('inbox:close-composer', (el)=>{
            close();
        });
    }

    function startConversation(){

        if(!selectedParticipants) return;

        callbora
            .post(
                'api/modules/inbox/create-direct',
                {
                    //user_id:selectedUser.id
                    // participants: selectedParticipants.map(p => p.id)
                    participants: selectedParticipants.map(p => ({
                        id: p.id,
                        type: p.type
                    }))
                }
            )
            .then(res=>{

                if(!res.success) return;

                close();

                navigation.go(
                    `portal/inbox/thread/${res.thread.id}`
                );

            });
    }

    function renderResults(users){

        const list = el.querySelector('.participant-results');

        list.innerHTML = '';

        users.forEach(u=>{

            const li = document.createElement('li');

            li.textContent =
                `${u.username} (${u.email})`;

            li.addEventListener('click', ()=>{
                const exists = selectedParticipants.find(p => p.id === u.id);

                if(exists){
                    selectedParticipants = selectedParticipants.filter(p => p.id !== u.id);
                    li.classList.remove('selected');
                } else {
                    selectedParticipants.push(u);
                    li.classList.add('selected');
                }

                el.querySelector('.start-btn').disabled =
                    selectedParticipants.length === 0;

            });

            list.appendChild(li);

        });

    }

    function isSameParticipant(a, b){
        return String(a.id) === String(b.id)
            && String(a.type) === String(b.type);
    }

    function open(){

        el.hidden = false;

        requestAnimationFrame(()=>{
            el.classList.add('open');
        });

        el.querySelector('.participant-search')?.focus();

        preloadSuggestions();
    }

    function close(){

        el.classList.remove('open');

        setTimeout(()=>{
            el.hidden = true;
        },250);

    }

    async function preloadSuggestions(){

        const list = el.querySelector('.participant-results');

        list.innerHTML = '<li class="loading">Loading...</li>';

        try{
            const res = await callbora.get(
                'api/modules/inbox/suggestions'
            );

            // renderResults(res.data || []);
            renderSuggestions(res.data || []);
            
        }
        catch(e){
            list.innerHTML = '<li class="error">Failed to load</li>';
        }
    }

    function renderSuggestions(data){

        const list = el.querySelector('.participant-results');
        list.innerHTML = '';

        const renderGroup = (title, users) => {

            if(!users || !users.length) return;

            const header = document.createElement('li');
            header.className = 'group-title';
            header.textContent = title;
            list.appendChild(header);

            users.forEach(raw => {
                const u = normalizeParticipant(raw);

                if(u.type === 'bot'){
                    list.appendChild(createBotItem(u));
                } else {
                    list.appendChild(createUserItem(u));
                }
            });
        };

        renderGroup('Recent', data.recent);
        renderGroup('Frequent', data.frequent);
        renderGroup('Bots', data.bots);
        renderGroup('Others', data.others);
    }

    function createUserItem(u){

        const li = document.createElement('li');

        li.innerHTML = `
            <div class="user">
                <span class="name">${u.username || u.name}</span>
                <span class="meta">${u.email || ''}</span>
            </div>
        `;

        li.addEventListener('click', ()=> toggleParticipant(u, li));

        return li;
    }

    function createBotItem(u){

        const li = document.createElement('li');

        li.innerHTML = `
            <div class="${u.entity_type}">
                <span class="name">${u.username||u.name}</span>
                <span class="meta">${u.email || ''}</span>
            </div>
        `;

        li.addEventListener('click', ()=> toggleParticipant(u, li));

        return li;
    }

    function normalizeParticipant(u){
        return {
            id: String(u.id),
            type: u.type || 'user',     // 🔥 align with backend
            name: u.name || u.username || '',
            avatar: u.avatar || '',
            bot_type: u.bot_type || null
        };
    }

    function toggleParticipant(rawUser, el){

        const user = normalizeParticipant(rawUser);

        const index = selectedParticipants.findIndex(p => isSameParticipant(p, user));

        if(index !== -1){
            selectedParticipants.splice(index, 1);
            el.classList.remove('selected');
        } else {
            selectedParticipants.push(user);
            el.classList.add('selected');
        }

        updateSelectedUI();

        el.closest('.inbox-composer')
            .querySelector('.start-btn').disabled =
            selectedParticipants.length === 0;
    }

    function toggleParticipantO(user, el){

        // const index = selectedParticipants.findIndex(p => p.id === user.id);
        const index = selectedParticipants.findIndex(p => isSameParticipant(p, user));

        if(index !== -1){
            // remove
            selectedParticipants.splice(index, 1);
            el.classList.remove('selected');
        } else {
            // 🟢 add
            selectedParticipants.push(user);
            el.classList.add('selected');
        }

        updateSelectedUI();

        // Enable/disable button
        el.closest('.inbox-composer')
            .querySelector('.start-btn').disabled =
            selectedParticipants.length === 0;
    }


    function updateSelectedUI(){

        const container = el.querySelector('.selected-participants');

        if(!container) return;

        container.innerHTML = '';

        selectedParticipants.forEach(user => {

            const chip = document.createElement('div');
            chip.className = 'participant-chip';

            chip.innerHTML = `
                ${user.name}
                <span class="remove">&times;</span>
            `;

            chip.querySelector('.remove').addEventListener('click', (e)=>{
                e.stopPropagation();

                selectedParticipants = selectedParticipants.filter(p => p.id !== user.id);

                // also unselect in list
                el.querySelectorAll('.participant-results li').forEach(li => {
                    if(li.textContent.includes(user.name)){
                        li.classList.remove('selected');
                    }
                });

                updateSelectedUI();

                el.querySelector('.start-btn').disabled =
                    selectedParticipants.length === 0;
            });

            container.appendChild(chip);
        });
    }

    return {
        init,
        open,
        close
    };

},{
    //requires:['realtime'],
    activateOn: (route) => route.startsWith('portal/inbox')
});