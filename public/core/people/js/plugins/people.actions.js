__BORA_REGISTER_PLUGIN__(
'people.actions',

async function(scope){

    const uiActions  = await scope.getService('ui.actions');
    const popup      = await scope.getPlugin('popup');
    const callbora   = await scope.getService('callbora');
    const navigation = await scope.getService('navigation');
    const bNavigator = await scope.getService('navigator');

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

    function personClaim(el){
        const id = $(el)
            .data('id');

        if (!id) return;

        bNavigator.go({
            route:'person.invite',
            params:{
                id:id
            },
            surface:'popup'
        });
    }

    function claimPerson(el){
        const token = $(el)
            .data('token');

        if (token) return;

        callbora.post(`api/modules/people/person/claim`, {
            token: token
        }).then(function(response){

            if(response.success){
                alertBora.success(response.message||'Claim successful.');

                if(response.redirect){
                    navigation.go(response.redirect);
                }
                
            } else {
                alertBora.error(response.message || 'Claim Failed');
            }

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
            'person.claim.invite',
            personClaim 
        );

        uiActions.register(
            'people.claim.person',
            claimPerson
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

        uiActions.register('person.delete', (el)=>{
            let personId = $(el).data('id');

            alertBora.prompt(
                '<h3>Confirm Action</h3>Enter your password to continue',
                {
                    html: true,
                    prompt: '<input type="password" name="password" placeholder="Password">'
                }
            ).then(function(det){

                let password = btoa(det.password);

                callbora.post(`api/modules/people/person/${personId}/delete`, {
                    password: password
                }).then(function(response){
                    if(response.success){
                        alertBora.success('Person soft deleted');

                        //remove item
                        $('.person-card[data-person="'+personId+'"]').addClass('deleted');
                        
                        scope.emit('people.back');

                    } else {
                        alertBora.error(response.message || 'Failed');
                    }

                });

            }); 

        });

        uiActions.register('person.restore', (el)=>{
            let personId = $(el).data('id');

            alertBora.prompt(
                '<h3>Confirm Action</h3>Enter your password to continue',
                {
                    html: true,
                    prompt: '<input type="password" name="password" placeholder="Password">'
                }
            ).then(function(det){

                let password = btoa(det.password);

                callbora.post(`api/modules/people/person/${personId}/restore`, {
                    password: password
                }).then(function(response){

                    if(response.success){
                        alertBora.success('Person eestore');

                        //Restore item
                        $('.person-card[data-person="'+personId+'"]').removeClass('deleted');

                        if(response.redirect){
                           navigation.go(response.redirect);
                        }
                        
                    } else {
                        alertBora.error(response.message || 'Failed');
                    }

                });

            }); 

        });

        uiActions.register('person.force-delete', (el)=>{
            let personId = $(el).data('id');

            alertBora.prompt(
                '<h3>Confirm Action</h3>Enter your password to continue',
                {
                    html: true,
                    prompt: '<input type="password" name="password" placeholder="Password">'
                }
            ).then(function(det){

                let password = btoa(det.password);

                callbora.post(`api/modules/people/person/${personId}/forcedelete`, {
                    password: password
                }).then(function(response){

                    if(response.success){
                        alertBora.success('Person deleted');

                        //remove item
                        $('.person-card[data-person="'+personId+'"]').remove();

                        scope.emit('people.back');
                    } else {
                        alertBora.error(response.message || 'Failed');
                    }

                });

            }); 

        });

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
        // alert('People ACtions mounted');
        state.mounted = true;

        init();

    }

    function unmount(){

        if(!state.mounted){
            return;
        }
        // alert('People ACtions unmounted');
        state.mounted = false;

    }

    return {
        mount,
        unmount,
        init
    };

},{
    faces:['client']
}
);