__BORA_REGISTER_PLUGIN__(
'breadcrumbs.plugin',
async function(scope){

    const hooks = await scope.getService('hooks');
    const breadcrumbs = await scope.getService('breadcrumbs');

    let $container;

    function mount(){
        $container = $('.breadcrumb');

        hooks?.add('breadcrumbs:changed', render);

        scope.on('route:changed', async ({url:url}) => {
            // optional: pass last known response if you have it
            scope.emit('breadcrumbs:resolve', {
                url: url,
                response:null
            });

        });

        console.log('[Breadcrumbs] mounted');
    }

    function render(list){
        if (!$container || !$container.length) return;

        const html = list.map((item, i) => {

            if (item.current || i === list.length - 1){
                return `<span class="current">${item.label}</span>`;
            }

            if (item.href){
                return `<a class="jx" href="${item.href}">${item.label}</a>`;
            }

            return `<span>${item.label}</span>`;

        }).join(' <span class="sep">»</span> ');

        $container.html(html);
    }

    return { mount, render };
});