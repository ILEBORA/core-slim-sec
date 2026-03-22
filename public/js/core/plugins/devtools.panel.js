__BORA_REGISTER_PLUGIN__('DevToolsPanel', async function(scope){

    const runtime = await scope.runtimeInstance;

    let el = null;

    function create(){

        if(el) return;

        el = document.createElement('div');

        el.id = '__bora_devtools__';

        Object.assign(el.style, {
            position: 'fixed',
            bottom: '10px',
            right: '10px',
            width: '320px',
            maxHeight: '50vh',
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

    function render(){

        if(!el) return;

        const timings = runtime.__timings || new Map();

        if(!timings.size){
            el.innerHTML = '<div>No plugin activity yet</div>';
            return;
        }

        let html = `<div style="margin-bottom:6px;font-weight:bold;">Bora DevTools</div>`;

        html += `<table style="width:100%;border-collapse:collapse;">`;

        html += `
            <thead>
                <tr>
                    <th align="left">Plugin</th>
                    <th>Mt</th>
                    <th>Avg</th>
                    <th>Max</th>
                </tr>
            </thead>
            <tbody>
        `;

        timings.forEach((t, name) => {
            const slow = t.max > 20 ? 'color:red;' : '';
            html += `
                <tr>
                    <td>${name}</td>
                    <td align="center">${t.count}</td>
                    <td align="right">${t.avg.toFixed(1)}</td>
                    <td align="right" style="${slow}">${t.max.toFixed(1)}</td>
                </tr>
            `;
        });

        html += `</tbody></table>`;

        el.innerHTML = html;
    }

    function mount(){
        // alert('mount dev panel');
        if(!scope.config.dev) return;
        console.log('[DevToolPanel] mounted');
        // alert('dev panel already mounted');

        create();

        // listen for updates
        scope.on('plugin:timing', render);

        // runtime.__timings.clear();

        render();

        console.log('[DevToolsPanel] mounted');

        document.addEventListener('keydown', e => {
            if(e.key === '`'){
                el.style.display = el.style.display === 'none' ? 'block' : 'none';
            }
        });
    }

    return { mount };

}, {
    // requires:['devtools']
    // faces: ['guest','client','admin'] // always visible in dev
});