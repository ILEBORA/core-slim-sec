__BORA_REGISTER_PLUGIN__('InboxComposer', function(scope){

    const callbora   = scope.getService('callbora');
    const navigation = scope.getService('navigation');

    let el;
    let selectedUser = null;
    let bound = false;

    function mount(){

        el = document.querySelector('.inbox-composer');

        if(!el || bound) return;

        bind();

        bound = true;
    }

    function bind(){

        el.querySelector('.close')
            ?.addEventListener('click', close);

        const input = el.querySelector('.participant-search');
        const list  = el.querySelector('.participant-results');

        let timer;

        input?.addEventListener('input', ()=>{

            clearTimeout(timer);

            const q = input.value.trim();

            if(q.length < 2){
                list.innerHTML = '';
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

        el.querySelector('.start-btn')
            ?.addEventListener('click', startConversation);
    }

    function startConversation(){

        if(!selectedUser) return;

        callbora
            .post(
                'api/modules/inbox/create-direct',
                {user_id:selectedUser.id}
            )
            .then(res=>{

                if(!res.success) return;

                close();

                navigation.go(
                    `portal/inbox/show/${res.thread.id}`
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

                selectedUser = u;

                list
                    .querySelectorAll('li')
                    .forEach(x=>x.classList.remove('selected'));

                li.classList.add('selected');

                el.querySelector('.start-btn').disabled = false;

            });

            list.appendChild(li);

        });

    }

    function open(){

        el.hidden = false;

        requestAnimationFrame(()=>{
            el.classList.add('open');
        });

        el.querySelector('.participant-search')?.focus();
    }

    function close(){

        el.classList.remove('open');

        setTimeout(()=>{
            el.hidden = true;
        },250);

    }

    return {
        mount,
        open,
        close
    };

});