__BORA_REGISTER_PLUGIN__(
'people.actions',

async function(scope){

    const uiActions  = await scope.getService('ui.actions');
    const popup      = await scope.getPlugin('popup');
    const callbora   = await scope.getService('callbora');
    const navigation = await scope.getService('navigation');

    const state = {
        initialized:false,
        mounted:false
    };

    async function ensureController(){

        return await scope.getPlugin(
            'people.controller'
        );

    }

    function openPersonEdit(personId){

        popup.open({
            mode:'form',
            module:'people',
            group:'person',
            tab:'edit',
            view:'edit',
            id:personId,
            size:'md'
        });

    }

    function registerActions(){

        /* =========================
           OPEN PERSON
        ========================= */

        uiActions.register(
            'people:open',

            async (el)=>{

                await ensureController();

                scope.emit(
                    'people.person.open',
                    {
                        personId:
                            $(el).data('person')
                    }
                );

            }
        );

        /* =========================
           BACK
        ========================= */

        uiActions.register(
            'people.back',

            async ()=>{

                await ensureController();

                scope.emit('people.back');

            }
        );

        /* =========================
           FOLLOW
        ========================= */

        uiActions.register(
            'people:follow',

            async (el)=>{

                await ensureController();

                scope.emit(
                    'people.follow.toggle',
                    {
                        personId:
                            $(el).data('person'),

                        isFollowing:
                            $(el)
                                .text()
                                .trim() === 'Following'
                    }
                );

            }
        );

        /* =========================
           PERSON VIEW
        ========================= */

        uiActions.register(
            'person.view',

            async (el)=>{

                await ensureController();

                const root =
                    $(el)
                        .closest('.person-view');

                scope.emit(
                    'people.tab.changed',
                    {
                        tab:'profile',

                        personId:
                            $(el).data('id'),

                        root: root[0]
                    }
                );

            }
        );

        /* =========================
           CONNECTIONS
        ========================= */

        uiActions.register(
            'person.connections',

            async (el)=>{

                await ensureController();

                const root =
                    $(el)
                        .closest('.person-view');

                scope.emit(
                    'people.tab.changed',
                    {
                        tab:'connections',

                        personId:
                            $(el).data('id'),

                        root: root[0]
                    }
                );

            }
        );

        /* =========================
           EDIT
        ========================= */

        uiActions.register(
            'person.edit',

            (el)=>{

                openPersonEdit(
                    $(el).data('id')
                );

            }
        );

        uiActions.register(
            'person.link.invite',

            (el)=>{

                alertBora.alert('Person Invite feature is disabled!');

            }
        );

        /* =========================
           MESSAGE
        ========================= */

        uiActions.register(
            'people:message',

            async (el)=>{

                const userId =
                    $(el).data('id');

                const res =
                    await callbora.post(
                        'api/modules/inbox/create-direct',
                        {
                            participants:[
                                {
                                    id:userId,
                                    type:'user'
                                }
                            ]
                        }
                    );

                if(!res.success){
                    return;
                }

                navigation.go(
                    `portal/inbox/thread/${res.thread.id}`
                );

            }
        );

        /* =========================
           NEW PERSON
        ========================= */

        scope.on(
            'people.person.new',

            ()=>{

                popup.open({
                    mode:'form',
                    module:'people',
                    group:'person',
                    view:'add',
                    size:'md'
                });

            }
        );

    }

    function init(){

        if(state.initialized){
            return;
        }

        state.initialized = true;

        registerActions();

    }

    function mount(){

        if(state.mounted){
            return;
        }

        state.mounted = true;

    }

    function unmount(){

        if(!state.mounted){
            return;
        }

        state.mounted = false;

    }

    init();

    return {
        mount,
        unmount,
        init
    };

},{
    faces:['client']
});