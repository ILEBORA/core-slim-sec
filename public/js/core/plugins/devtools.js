__BORA_REGISTER_PLUGIN__('DevTools', async function(scope){

    const config   = scope.config || {};
    const runtime  = scope.runtimeInstance;
    const devtools = await scope.getService('devtools');

    let el = null;
    let activeTab = 'perf';
    let interval = null;

    /* =========================
       CREATE PANEL
    ========================= */

    function create(){

        if(el) return;

        el = document.createElement('div');
        el.id = '__bora_devtools__';

        Object.assign(el.style, {
            position: 'fixed',
            bottom: '10px',
            right: '10px',
            width: '360px',
            maxHeight: '65vh',
            overflow: 'auto',
            background: '#111',
            color: '#0f0',
            fontSize: '12px',
            fontFamily: 'monospace',
            padding: '10px',
            borderRadius: '8px',
            zIndex: 999999,
            boxShadow: '0 0 10px rgba(0,0,0,0.5)'
        });

        $(function(){
            document.body.appendChild(el);
        });
    }

    /* =========================
       RENDER
    ========================= */

    async function render(){

        if(!el) return;

        let html = `
            <div style="margin-bottom:6px;font-weight:bold;">
                Bora DevTools
            </div>
            
            <div style="margin-bottom:8px;background-color:#ccc;">
                <button data-tab="perf">Perf</button>
                <button data-tab="rt">Realtime</button>
                <button data-tab="sys">System</button>
            </div>
        `;

        if(activeTab === 'perf') html += await renderPerf();
        if(activeTab === 'rt')   html += await renderRealtime();
        if(activeTab === 'sys')  html += await renderSystem();

        el.innerHTML = html;

        bindEvents();
    }

    /* =========================
       PERF TAB
    ========================= */

    async function renderPerf(){

        const runtime  = scope.runtimeInstance;
        const timings = runtime.__timings || new Map();

        if(!timings.size){
            return `<div>No plugin activity yet</div>`;
        }

        let html = `<table style="width:100%">`;

        html += `
            <tr>
                <th align="left">Plugin</th>
                <th>Mt</th>
                <th>Avg</th>
                <th>Max</th>
            </tr>
        `;

        timings.forEach((t, name) => {

            const slow = t.max > 20 ? 'style="color:red"' : '';

            html += `
                <tr>
                    <td>${name}</td>
                    <td align="center">${t.count}</td>
                    <td align="right">${t.avg.toFixed(1)}</td>
                    <td align="right" ${slow}>${t.max.toFixed(1)}</td>
                </tr>
            `;
        });

        html += `</table>`;

        return html;
    }

    /* =========================
       REALTIME TAB
    ========================= */

    async function renderRealtime(){

        const leader = await scope.getService('realtime.leader');
        const sse    = await scope.getService('realtime.sse');

        if(!leader){
            return `<div>No realtime service</div>`;
        }

        const isL = leader.isLeader?.();

        return `
            <div><b>Tab:</b> ${leader.getTabId?.() || '—'}</div>
            <div><b>Leader:</b> ${isL ? 'YES' : 'NO'}</div>
            <div><b>Epoch:</b> ${leader.getEpoch?.() ?? '—'}</div>
            <div><b>SSE:</b> ${sse?._raw?.ths_source ? 'CONNECTED' : 'IDLE'}</div>
            <div style="margin-top:6px;">
                <button data-force>Force Leader</button>
            </div>
        `;
    }

    /* =========================
       SYSTEM TAB
    ========================= */

    async function renderSystem(){

        const devtools = await scope.getService('devtools');
        const data = await devtools?.inspect();

        return `
            <div><b>Services:</b> ${data?.services.length}</div>
            <div><b>Plugins:</b> ${data?.plugins.length}</div>
            <div style="margin-top:6px;">
                <button data-dump>Dump State</button>
            </div>
        `;
    }

    /* =========================
       EVENTS
    ========================= */

    function bindEvents(){

        el.querySelectorAll('[data-tab]').forEach(btn => {
            btn.onclick = () => {
                activeTab = btn.dataset.tab;
                render();
            };
        });

        const dump = el.querySelector('[data-dump]');
        if(dump){
            dump.onclick = () => {
                console.log('[Dev Snapshot]', devtools.snapshot('manual'));
            };
        }

        const force = el.querySelector('[data-force]');
        if(force){
            force.onclick = () => {
                localStorage.removeItem('sse-leader-lock');
                setTimeout(render, 300);
            };
        }
    }

    /* =========================
       LIFECYCLE
    ========================= */

    function mount(){
        if(!config.dev) return;
        console.log('[DevTools] mounted');

        create();
        render();

        // expose globally
        globalThis.__BORA_DEV__ = devtools;

        // listen updates
        scope.on('plugin:timing', render);
        scope.on('realtime:leader-change', render);

        interval = setInterval(render, 2000);

        console.log('%c Bora DevTools Ready', 'color:#8b5cf6;font-weight:bold;');

        document.addEventListener('keydown', e => {
            if(e.key === '`'){
                el.style.display = el.style.display === 'none' ? 'block' : 'none';
            }
        });
    }

    function unmount(){

        if(interval){
            clearInterval(interval);
            interval = null;
        }

        if(el){
            el.remove();
            el = null;
        }
    }

    return { mount, unmount };

}, {
    // requires:['devtools'],
    faces: ['client','admin','guest']
});