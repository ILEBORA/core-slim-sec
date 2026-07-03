__BORA_REGISTER_PLUGIN__(
'people.controller',

async function(scope){

    const callbora    = await scope.getService('callbora');
    const navigation  = await scope.getService('navigation');
    const breadcrumbs = await scope.getService('breadcrumbs');

    const ui     = new PeopleUI(scope);
    const loader = new PeopleLoader(scope, callbora);

    const follow = new PeopleFollow(
        callbora,
        ui,
        loader
    );

    const api = new PeopleAPI({
        ui,
        loader,
        follow
    });

    let initialized = false;

    function init(){

        if(initialized) return;

        initialized = true;

        scope.on(
            'people.person.open',
            async ({personId})=>{
                
                breadcrumbs.set([
                    {
                        label:'People',
                        href:'portal/people'
                    },
                    {
                        label:'Loading...',
                        current:true
                    }
                ]);

                await api.openProfile(personId);

            }
        );

        scope.on(
            'people.follow.toggle',
            async ({personId, isFollowing})=>{

                await api.toggleFollow(
                    personId,
                    isFollowing
                );

            }
        );

        scope.on(
            'people.back',
            ()=>{
                ui.handleBack();
                
                ui.clearDetail();

            }
        );

        scope.on(
    'people.tab.changed',

    async ({tab, personId, root})=>{

            // optional immediate ui feedback
            scope.emit(
                'people.tab.ui',
                {
                    tab,
                    personId,
                    root
                }
            );

            await api.loadTab(
                personId,
                tab
            );

        }
    );

    }

    init();

    return {
        init
    };

},{
    faces:['client']
});