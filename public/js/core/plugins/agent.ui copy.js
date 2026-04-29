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
            const serverState = await callbora.post(
                                    `api/modules/app/agent/state`
                                );
            this.state = {
                ...this.state,
                ...serverState
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

    await AgentState.load();
    await AgentState.syncFromServer();

    if (!$('#bai-agent').length) {
        $('body').append(`
            <div id="bai-agent">
                <div class="agent-window"></div>
                <input type="text" class="agent-input" placeholder="Ask me..." />
            </div>
        `);
    }

    $(document).on('keypress', '.agent-input', async function(e){
        if (e.which === 13) {

            const text = $(this).val();
            $(this).val('');

            // optimistic UI (optional)
            $('.agent-window').append(`<div class="user">${text}</div>`);

            const res = await callbora('agent.handle', { text });

            // apply server updates
            if (res.context_updates) {
                await AgentState.applyUpdate(res.context_updates);
            }

            $('.agent-window').append(`<div class="bot">${res.text}</div>`);
        }
    });

});