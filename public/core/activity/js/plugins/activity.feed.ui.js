__BORA_REGISTER_PLUGIN__('activity.feed.ui', async function(scope){

    const feed = await scope.getService('activity.feed');
    const sse  = await scope.getService('realtime.sse');

    let el;
    let scopeName='home';

    // 🔒 Internal state
    const state = {
        mounted: false
    };

    function mount(){
        if (state.mounted) return;
        state.mounted = true;
        // alert('here');
        console.log('[activity.feed.ui] mounted');
        
        waitForElement('#activityFeedNew', (node) => {
            el = node;
            scopeName = el.dataset.scope || 'home';
            console.log('Proceed...');
            // load();
            bindRealtime();
        });
    }

    function waitForElement(selector, callback){
        const el = document.querySelector(selector);
        if(el) return callback(el);

        const observer = new MutationObserver(() => {
            const el = document.querySelector(selector);
            if(el){
                observer.disconnect();
                callback(el);
            }
        });

        observer.observe(document.body, { childList: true, subtree: true });
    }

    function unmount(){
        if (!state.mounted) return; // ⚠️ FIXED (was wrong)
        state.mounted = false;

        sse?.off?.('feed.activity.updated', handleUpdated);
        sse?.off?.('feed.activity.deleted', handleDeleted);
    }

    async function load(reset=false){

        const data = await feed.load({
            scopeName,
            reset
        });

        if(!data.length) return;
        
        $(el).empty();

        data.forEach(item=>{
            //Norma Append DESC
            $(el).append(item.html);
        });
    }

    function addToTimeline(html){
        $(el).prepend(html);
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

    return { mount, unmount, addToTimeline };

},{
    requires:['activity.feed','realtime.sse'],
    activateOn: (route) => route.startsWith('portal/activity')
});
