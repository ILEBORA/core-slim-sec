__BORA_REGISTER_PLUGIN__('activity.stories.feed', async function(scope){

    const sse = await scope.getService('realtime.sse');

    const state = {
        mounted: false
    };

    function mount(){

        if(state.mounted) return;
        state.mounted = true;

        bind();

        if(sse){
            sse.on('stories', refresh);
        }
    }

    function unmount(){

        if(!state.mounted) return;
        state.mounted = false;

        sse?.off?.('stories', refresh);
    }

    function bind(){

        $(document).on('click',
            '.stories-container .story-item',
            handleOpenStory
        );

    }

    async function refresh(){

        $.getJSON('api/modules/activity/stories/feed', function(resp){

            if(!resp.success) return;

            render(resp.data);

        });

    }

    function render(groups){

        const $c = $('#storiesContainer');

        if(!$c.length) return;

        $c.empty();

        groups.forEach(group => {

            const first = group[0];

            const viewed = group.every(s => s.viewed);

            $c.append(`
                <div
                    class="story-item ${viewed ? 'seen' : 'unseen'}"
                    data-action="story.open"
                    data-story="${first.id}"
                    data-actor="${first.actor_id}"
                >

                    <div class="story-avatar">
                        <img src="${first.payload.preview}">
                    </div>

                    <div class="story-label">
                        ${first._actor?.username || 'You'}
                    </div>

                </div>
            `);

        });

    }

    function handleOpenStory(){

        // delegated to actions plugin
    }

    return {
        mount,
        unmount,
        refresh,
        render
    };

},{
    requires:['realtime']
});