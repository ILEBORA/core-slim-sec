__BORA_REGISTER_PLUGIN__('ActivityFeedUI', function(scope){

    const feed = scope.getService('activity.feed');
    const sse  = scope.getService('realtime.sse');

    let el;
    let scopeName='home';

    function mount(){

        el = document.querySelector('#activityFeed');
        if(!el) return;

        scopeName = el.dataset.scope || 'home';

        load();

        bindRealtime();
    }

    function unmount(){
        sse?.off?.('feed.activity.updated', handleUpdated);
        sse?.off?.('feed.activity.deleted', handleDeleted);
    }

    async function load(reset=false){

        const data = await feed.load({
            scopeName,
            reset
        });

        if(!data.length) return;

        data.forEach(item=>{
            $(el).append(item.html);
        });
    }

    function bindRealtime(){

        if(!sse) return;

        sse.on('feed.activity.updated', handleUpdated);
        sse.on('feed.activity.deleted', handleDeleted);
    }

    function handleUpdated(event){

        const batch = event.data.events || [];

        batch.forEach(ev=>{

            const id = ev.payload.id;
            const payload = ev.payload;

            const $existing = $(`.activity-item[data-id="${id}"]`);

            if($existing.length){
                $existing.replaceWith(payload.html);
            }else{
                $(el).prepend(payload.html);
            }
        });

    }

    function handleDeleted(event){

        const id = event.data.id;

        $(`.activity-item[data-id="${id}"]`).remove();
    }

    return { mount, unmount };

},{
    requires:['activity.feed','realtime.sse'],
    //activateOn:(route)=>route.startsWith('portal/activity')
});

alert('Activity Feed Plugin');