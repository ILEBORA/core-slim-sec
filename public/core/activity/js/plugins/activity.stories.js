__BORA_REGISTER_PLUGIN__('activity.stories', async function(scope){

    const sse = await scope.getService('realtime.sse');

    const state = {
        mounted: false
    };

    function mount(){
        if (state.mounted) return;
        state.mounted = true;

        loadStories();

        if(sse){
            sse.on('stories', handleStories);
        }
    }

    function unmount(){
        if (!state.mounted) return;
        state.mounted = false;
        
        sse?.off?.('stories', handleStories);
    }

    function loadStories(){

        $.getJSON('api/modules/activity/stories/feed', resp=>{

            if(!resp.ok) return;

            render(resp.data);
        });
    }

    function render(groups){

        const $c = $('#storiesContainer').empty();

        groups.forEach(group=>{

            const first = group[0];
            const viewed = group.every(s=>s.viewed);

            $c.append(`
                <div class="story-item ${viewed?'seen':''}"
                     data-story="${first.id}">
                    <div class="story-avatar">
                        <img src="${first.payload.snapshot.thumb}">
                    </div>
                    <div class="story-label">Story</div>
                </div>
            `);

        });
    }

    function handleStories(){
        loadStories();
    }

    return { mount, unmount };

},{
    requires:['realtime.sse'],
    activateOn: (route) => route.startsWith('portal/activity/stories')
});