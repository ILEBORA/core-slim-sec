__BORA_REGISTER_PLUGIN__(
'people.workspace',

async function(scope){

    const callbora       = await scope.getService('callbora');
    // const uiInteractions = await scope.getPlugin(
    //     'people.ui.interactions'
    // );

    const navigation = await scope.getService(
        'navigation'
    );

    const ui = new PeopleUI(scope);

    const loader =
        new PeopleLoader(
            scope,
            callbora
        );

    // const presence =
    //     new PeoplePresence(ui);

    const tabs =
        new PeopleTabs(scope);

    const notifications =
        new PeopleNotifications(
            ui,
            navigation
        );

    // const follow =
    //     new PeopleFollow(
    //         callbora,
    //         ui,
    //         loader
    //     );

    // const realtime =
    //     new PeopleRealtime(
    //         scope,
    //         ui,
    //         presence,
    //         notifications,
    //         follow,
    //         loader
    //     );

    const state = {
        mounted:false
    };

    function bindRouteEvents(){
        scope.on(
            'page.loaded',

            ()=>{
                
                loader.resolvePersonFromRoute();

            }
        );

        scope.on(
            'people.tab.ui',

            ({tab, personId, root})=>{

                tabs.setTab(
                    root,
                    personId,
                    tab
                );

            }
        );

    }

    async function mount(){
        if(state.mounted){
            return;
        }
        // alert('People Mounted');
        state.mounted = true;
        
        ui.bind();

        // realtime.initUserChannel();

        bindRouteEvents();

        // uiInteractions.init();

        await attachInteractions();

    }

    function unmount(){

        if(!state.mounted){
            return;
        }
        // alert('People unMounted');
        state.mounted = false;

        ui.unbind();

        // realtime.destroy();

        scope.off('page.loaded');
        scope.off('people.tab.ui');

    }

    async function attachInteractions(){

        const uiInteractions =
            await scope.getPlugin(
                'people.ui.interactions'
            );

        uiInteractions.init();

    }

    return {
        mount,
        unmount
    };

}
);