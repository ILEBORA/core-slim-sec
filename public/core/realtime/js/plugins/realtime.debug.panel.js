__BORA_REGISTER_PLUGIN__('RealtimeDebugPanel', async function(scope){

    if(!scope.config.dev || !window.REALTIME_DEBUG){
        return {};
    }

    const app = await scope.runtimeInstance;

    let el = null;
    let interval = null;

    function create(){

        if(el) return;

        el = document.createElement('div');
        el.id = 'realtime-debug-overlay';

        el.innerHTML = `
            <div class="rt-header">Realtime Debug</div>
            <div class="rt-row"><b>Tab</b>: <span data-tab></span></div>
            <div class="rt-row"><b>Leader</b>: <span data-leader></span></div>
            <div class="rt-row"><b>Epoch</b>: <span data-epoch></span></div>
            <div class="rt-row"><b>SSE</b>: <span data-sse></span></div>
            <div class="rt-actions">
                <button data-force>Force Leader</button>
            </div>
        `;

        $(function(){
            const anchor = document.querySelector('.main-wrapper');

            if (anchor && anchor.parentNode) {
                anchor.parentNode.insertBefore(el, anchor.nextSibling);
            } else {
                document.body.appendChild(el);
            }
        });
    }

    async function refresh(){

        const leader = await scope.getService('realtime.leader');
        const sse    = await scope.getService('realtime.sse');

        if(!leader) return;

        const isL = leader.isLeader?.();

        el.querySelector('[data-tab]').textContent =
            leader.getTabId?.() || '—';

        el.querySelector('[data-leader]').textContent =
            isL ? 'YES' : 'NO';

        el.querySelector('[data-epoch]').textContent =
            leader.getEpoch?.() ?? '—';

        el.querySelector('[data-sse]').textContent =
            sse?._raw?.ths_source ? 'CONNECTED' : 'IDLE';

        el.classList.toggle('rt-leader', !!isL);
    }

    function mount(){

        create();
        refresh();

        scope.on('realtime:leader-change', refresh);

        interval = setInterval(refresh, 2000);

        const btn = el.querySelector('[data-force]');
        if(btn){
            btn.onclick = () => {
                localStorage.removeItem('sse-leader-lock');
                setTimeout(refresh, 300);
            };
        }

        console.log('[RealtimeDebugPanel] mounted');
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

        console.log('[RealtimeDebugPanel] unmounted');
    }

    return { mount, unmount };

}, {
    // faces: ['client', 'admin'] // or include 'guest' if needed
});