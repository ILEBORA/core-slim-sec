__BORA_REGISTER_PLUGIN__(
'breadcrumbs.plugin',
async function(scope){

    const hooks = await scope.getService('hooks');
    const breadcrumbs = await scope.getService('breadcrumbs');

    // let $container;
    const getContainer = scope.bindDom('.breadcrumb');

    const state = {
        mounted: false,
        initialized:false
    };

    function mount(){
        if (state.mounted) return;
        state.mounted = true;
        // const $container = getContainer();

        scope.on('page.afterLoad', ()=>{
            // TODO:: init bread
            // alert('page.afterLoad');
        });

        scope.on('breadcrumbs:changed', render);

         // INITIAL RENDER
        render(breadcrumbs.get());

        // hooks?.add('breadcrumbs:changed', render);

        scope.on('route:changed', async ({url:url}) => {
            // alert('route changed bread here :: ' + url);
            // optional: pass last known response if you have it
            breadcrumbs.clear();

            scope.emit('breadcrumbs:resolve', {
                url: url,
                response:null
            });

        });

        console.log('[Breadcrumbs] mounted');
    }

    function render(list){
        // alert('render');

        const $container = getContainer();
        if (!$container || !$container.length){ alert('container not found'); return;}

        // $container = $('.breadcrumb');

        const html = list.map((item, i) => {

            if (item.current || i === list.length - 1){
                return `<span class="current">${item.label}</span>`;
            }

            if (item.href){
                return `<a class="jx" href="${item.href}">${item.label}</a>`;
            }

            return `<span>${item.label}</span>`;

        }).join(' <span class="sep">»</span> ');
        // alert('content: '+html);
        $container.html(html);

        // We should not need this
        $(function(){
            //Extra bind
            // alert('here');
            $cnt = $('.breadcrumb');
            if($cnt){
                $cnt.html(html);
            }
        });
    }

    function unmount(){
        state.mounted = false;
    }

    return { mount, unmount, render };
});