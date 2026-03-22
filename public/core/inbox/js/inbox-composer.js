__BORA_REGISTER_PLUGIN__('InboxComposer', async function(scope){

    const navigation = await scope.getService('navigation');

    let el;
    let selectedUser = null;

    function mount(){
        el = document.querySelector('.inbox-composer');
        if(!el) return;
        // alert('here');
        bind();
        //open();
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
                fetch(`api/modules/inbox/participants?q=${encodeURIComponent(q)}`)
                    .then(r=>r.json())
                    .then(res=>renderResults(res.data || []));
            },250);
        });
    }

    function open() {
        el.hidden = false;
        el.classList.add('open');
        el.querySelector('.participant-search')?.focus();

        el.querySelector('.start-btn')
            .addEventListener('click', () => {
                if (!selectedUser) return;

                fetch('api/modules/inbox/create-direct', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify({
                        user_id: selectedUser.id
                    })
                })
                .then(r => r.json())
                .then(res => {
                    if (!res.success) return;

                    close();

                    // navigate / load thread
                    window.location.href =
                        `portal/inbox/show/${res.thread.id}`;
                });
            });
    }

    function renderResults(users){

        const list = el.querySelector('.participant-results');
        list.innerHTML = '';

        users.forEach(u=>{
            const li = document.createElement('li');
            li.textContent = `${u.username} (${u.email})`;

            li.addEventListener('click', ()=>{
                selectedUser = u;
                li.classList.add('selected');
                el.querySelector('.start-btn').disabled = false;
            });

            list.appendChild(li);
        });
    }

    function close(){
        el.classList.remove('open');
        setTimeout(()=> el.hidden = true, 250);
    }



    return { mount, open,  close };
});