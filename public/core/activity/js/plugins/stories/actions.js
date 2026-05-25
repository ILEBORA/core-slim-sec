__BORA_REGISTER_PLUGIN__('activity.stories.actions', async function(scope){

    const popup = await scope.getPlugin('popup');
    const uiActions = await scope.getService('ui.actions');
                                                                                                                             

    const state = {
        initialized:false
    };

    init();

    function init(){

        if(state.initialized) return;

        state.initialized = true;

        
        uiActions.register('story.open', openStory);

        uiActions.register('story.create', createStory);

    }

    async function popupStory(el){

        const id = $(el)
            .data('story-id');

        bNavigator.go({

            route: 'stories.view',

            params:{ id },

            surface:'popup'
        });
    }

    async function openStory(el){
        // alert('openStory');
        const actorId =
            $(el).data('actor');

        if(!actorId) return;

        popup.open({
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

                viewer.mount(actorId);

            }
        });

    }

    async function createStory(){

        const bNavigator = await scope.getService('navigator');

        // console.log('bNavigator',bNavigator);

        bNavigator.go({

            route: 'stories.add',

            params:{},

            surface:'popup'
        });

    }

    return {};

});