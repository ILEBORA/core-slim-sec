__BORA_REGISTER_PLUGIN__('activity.stories', async function(scope){

    // const storyComposer = await scope.getPlugin('activity.story.composer');
    const sse           = await scope.getService('realtime.sse');
    // const storyComposer  = await scope.getPlugin('activity.story.composer');

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

        $(document).on('click', '.stories-container .story-item', async function () {
            const id = $(this).data('story');

            const popup = await scope.getPlugin('popup');

            popup.open({
                mode:'view',
                module:'activity',
                group:'stories',
                view:'story',
                id: id,
                tabs: [
                    {
                        id: 'view',
                        label: 'Stories',
                        url: `api/modules/activity/stories/${id}/view`
                    },
                    // {
                    //     id: 'likes',
                    //     label: 'Likes',
                    //     url: `api/modules/activity/view/likes/${id}`
                    // }
                ],

                activeTab: 'view'
            });

        });

        $(document).on('click', '#createStoryBtn', async function () {
            const popup = await scope.getPlugin('popup');

            popup.open({
                mode:'form',
                module:'activity',
                group:'stories',
                tab: 'add',
                view:'add',
                id:null,
                size:'md',
                onOpen: async () => {
                    // alert('add');
                    // setTimeout(function() {
                    //     storyComposer?.bindUI();
                    // }, 10);
                }
            });
        });
    }

    function unmount(){
        if (!state.mounted) return;
        state.mounted = false;
        
        sse?.off?.('stories', handleStories);
    }

    function loadStories(){

        $.getJSON('api/modules/activity/stories/feed', resp=>{

            if(!resp.success) return;

            render(resp.data);
        });
    }

    function render(groups){

        const $c = $('#storiesContainer').empty();

        groups.forEach(group => {

            const first  = group[0];
            const viewed = group.every(s => s.viewed);

            $c.append(`
                <div class="story-item ${viewed ? 'seen' : ''}"
                    data-story="${first.id}"
                    data-group='${JSON.stringify(group)}'>

                    <div class="story-avatar">
                        <img src="${first.payload.full}">
                    </div>

                    <div class="story-label">
                        ${first.actor?.username || 'You'}
                    </div>

                </div>
            `);

        });
    }

    function handleStories(){
        loadStories();
    }

    return { mount, unmount };

},{
    requires:['realtime'],
    activateOn: (route) => route.startsWith('portal/activity/stories')
});
