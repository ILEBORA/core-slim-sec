__BORA_REGISTER_PLUGIN__('agent.ui', async function(scope){

    const callbora = await scope.getService('callbora');

    const AgentDB = (() => {
        let db;

        async function init() {
            if (db) return db;

            db = await new Promise((resolve, reject) => {
                const req = indexedDB.open('bai-agent-db', 1);

                req.onupgradeneeded = e => {
                    const db = e.target.result;
                    db.createObjectStore('state');
                };

                req.onsuccess = e => resolve(e.target.result);
                req.onerror = reject;
            });

            return db;
        }

        async function get(key) {
            const db = await init();
            return new Promise((resolve) => {
                const tx = db.transaction('state', 'readonly');
                const store = tx.objectStore('state');
                const req = store.get(key);
                req.onsuccess = () => resolve(req.result);
                req.onerror = () => resolve(null);
            });
        }

        async function set(key, value) {
            const db = await init();
            return new Promise((resolve) => {
                const tx = db.transaction('state', 'readwrite');
                const store = tx.objectStore('state');
                store.put(value, key);
                tx.oncomplete = resolve;
            });
        }

        return { get, set };
    })();
    
    const AgentState = {
        state: {
            context: {},
            session: null
        },
        async load() {
            const saved = await AgentDB.get('agent_state');
            if (saved) {
                this.state = saved;
            }
        },

        async save() {
            await AgentDB.set('agent_state', this.state);
        },

        async syncFromServer() {
            const res = await callbora.get(
                                    `api/modules/app/agent/state`
                                );
            const serverState = res.data.state;
            this.state = {
                ...this.state,
                context: {
                    ...this.state.context,
                    ...serverState.context
                },
                session: serverState.session ?? this.state.session,
                meta: serverState.meta ?? this.state.meta
            };
            
            await this.save();
            this.render();
        },

        async applyUpdate(update) {
            this.state = {
                ...this.state,
                ...update
            };
            await this.save();
            this.render();
        },

        render() {
            // hook your UI here later
            console.log('Agent State:', this.state);
        }
    };
    // alert('this');
    async function mount(){ 
        // alerBora.alert('Mount bot');
        await AgentState.load();
        await AgentState.syncFromServer();

        if (!$('#bai-agent').length) {
            $('body').append(`
                <div id="bai-agent" class="collapsed">

                    <div class="agent-toggle"><img src="assets/images/bots/bai.png" alt="AI" /></div>

                    <div class="agent-panel">
                        <div class="agent-header">
                            <span>Bai Assistant</span>
                            <span class="close">✕</span>
                        </div>

                        <div class="agent-window"></div>

                        <div class="agent-input-wrap">
                            <input class="agent-input" placeholder="Ask me anything..." />
                        </div>
                    </div>

                </div>
            `);
        }

        const open = localStorage.getItem('agent_open');

        if (open === '1') {
            $('#bai-agent').removeClass('collapsed');
        }

        $(document).on('click', '.agent-toggle', function(){
            localStorage.setItem('agent_open', '1');
            $('#bai-agent').removeClass('collapsed');
        });

        $(document).on('click', '.agent-header .close', function(){
            localStorage.setItem('agent_open', '0');
            $('#bai-agent').addClass('collapsed');
        });

        $(document).off('keypress').on('keypress', '.agent-input', async function(e){
            if (e.which === 13) {

                const text = $(this).val();
                $(this).val('');

                // optimistic UI (optional)
                $('.agent-window').append(`<div class="user">${text}</div>`);

                const res = await callbora.post(`api/modules/app/agent/handle`,{ text });

                // apply server updates
                if (res.data.state) {
                    await AgentState.applyUpdate(res.data.state);
                }

                $('.agent-window').append(`<div class="bot">${res.data.text}</div>`);
            }
        });

    }

    return {
        mount
    };
    

},
{
    // activateOn: (route) => route.startsWith('bo/dev'),

    // faces: ['client', 'admin'],

    permissions: (appcore) => {
        if(!appcore) return false;
        return appcore.hasPermission('bots', 'assistant', true) === true;
    },
});