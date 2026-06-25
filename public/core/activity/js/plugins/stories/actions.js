__BORA_REGISTER_PLUGIN__('activity.stories.actions', async function(scope){

    const popup = await scope.getPlugin('popup');
    const uiActions = await scope.getService('ui.actions');
    const bNavigator = await scope.getService('navigator');
    // const viewer = await scope.getPlugin('activity.stories.viewer');
                                                                                                                             

    const state = {
        initialized:false
    };

    function mount(){
        if (state.mounted) return;
        state.mounted = true;

        // init();
    }

    init();

    function unmount(){
        if (!state.mounted) return;
        state.mounted = false;
        state.initialized = false;
    }

    function init(){

        if(state.initialized) return;

        state.initialized = true;

        
        uiActions.register('story.open', openStory);

        uiActions.register('story.create', createStory);

    }

    async function popupStory(el){
        
        const id =
            $(el).data('actor');
        
        if(!id) return;

        const bNavigator = await scope.getService('navigator');
        bNavigator.go({

            route: 'stories.view',

            params:{ id },

            surface:'popup',
            onLoaded: async (url)=>{
                // alert('here');
                const viewer = await scope.getPlugin(
                        'activity.stories.viewer'
                    );
                console.log('Viewer:', viewer);
                viewer?.open(id,
                    popupInstance
                );

                // alert('here finally');

            }
        });
    }

    async function openStory(el){
        // alert('openStory');
        const actorId =
            $(el).data('actor');
        // alert(actorId);
        if(!actorId) return;

        const popupInstance = await popup.open({
            mode:'view',
            module:'activity',
            group:'stories',
            view:'story',
            id: actorId,

            tabs:[
                {
                    id:'view',
                    label:'Stories',
                    url:`api/modules/activity/stories/${actorId}/view`
                }
            ],

            activeTab:'view',

            onLoaded: async ()=>{
                // alert('here');
                const viewer = await scope.getPlugin(
                        'activity.stories.viewer'
                    );

                viewer.open(
                    actorId,
                    popupInstance
                );

            }
        });

    }

    async function createStory(){
        const bNavigator = await scope.getService('navigator');
        bNavigator.go({

            route: 'stories.add',

            params:{},

            surface:'popup',

            onclose: async ()=>{
                alert('Refresh here');
                const feed = await scope.getPlugin('activity.stories.feed');
                feed.refresh();
            }
        });

    }

    // function unmount(){
    //     state.initialized = false;
    // }

    return {
        mount,
        unmount
    };

});