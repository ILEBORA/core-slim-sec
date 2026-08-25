__BORA_REGISTER_PLUGIN__(
'people.actions',

async function(scope){

    const uiActions  = await scope.getService('ui.actions');
    const popup      = await scope.getPlugin('popup');
    const callbora   = await scope.getService('callbora');
    const navigation = await scope.getService('navigation');
    const bNavigator = await scope.getService('navigator');

    const uiBindings = await  scope.getPlugin('ui.bindings');
    const appState = await scope.getService('state');
    const resources = await scope.getService('resources');
    

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

        scope.on(
            'realtime:people:person.updated',
        
            ({ payload }) => {
                // alert('Person editted');
                scope.emit(
                    'people.updated',
                    {
                        person: payload
                    }
                );

            }
        );

        scope.on(
            'realtime:people:person.presence',
        
            async ({ payload }) => {
                // alert('Person presence');
                // await resources.get('people');
                // await resources.get('presence');

                scope.emit(
                    'person.presence',
                    {
                        event: payload
                    }
                );

            }
        );

        uiBindings.bind();

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

    (async function(){
        // alert('here binder');
        //-------------------------------------------------
        // Initial State
        //-------------------------------------------------
    
        appState.set(
            'demo.name',
            'John'
        );
    
        appState.set(
            'demo.counter',
            0
        );
    
        appState.set(
            'demo.active',
            false
        );
    
        appState.set(
            'demo.visible',
            true
        );
    
        appState.set(
            'demo.disabled',
            false
        );
    
        appState.set(
            'demo.avatar',
            'https://picsum.photos/150?random=1'
        );
    
        appState.set(
            'demo.html',
            '<strong>Hello World</strong>'
        );
    
        appState.set(
            'demo.person',
            {
    
                first_name:'John',
    
                last_name:'Doe',
    
                age:25,
    
                gender:'Male'
    
            }
        );
    
        //-------------------------------------------------
        // Test Data
        //-------------------------------------------------
    
        const firstNames = [
    
            'John',
    
            'Mary',
    
            'Peter',
    
            'Alice',
    
            'James',
    
            'Jane'
    
        ];
    
        const lastNames = [
    
            'Doe',
    
            'Smith',
    
            'Brown',
    
            'Jones',
    
            'Taylor'
    
        ];
    
        const genders = [
    
            'Male',
    
            'Female'
    
        ];
    
        let counter = 0;
    
        //-------------------------------------------------
        // Random Updates
        //-------------------------------------------------
    
        setInterval(()=>{
            // console.log('Test Realtime...');
            counter++;
            
            const first =
    
                firstNames[
                    Math.floor(
                        Math.random()*
                        firstNames.length
                    )
                ];
    
            const last =
    
                lastNames[
                    Math.floor(
                        Math.random()*
                        lastNames.length
                    )
                ];
    
            const gender =
    
                genders[
                    Math.floor(
                        Math.random()*2
                    )
                ];
    
            const active =
                Math.random()>.5;
    
            const visible =
                Math.random()>.5;
    
            const disabled =
                Math.random()>.5;
    
            //-------------------------------------------------
            // Scalar
            //-------------------------------------------------
    
            appState.set(
                'demo.counter',
                counter
            );
    
            appState.set(
                'demo.name',
                first
            );
    
            appState.set(
                'demo.active',
                active
            );
    
            appState.set(
                'demo.visible',
                visible
            );
    
            appState.set(
                'demo.disabled',
                disabled
            );
    
            appState.set(
                'demo.avatar',
    
                'https://picsum.photos/150?random='+
    
                Math.floor(
                    Math.random()*1000
                )
    
            );
    
            appState.set(
    
                'demo.html',
    
                '<h3>'+first+'</h3>'+
    
                '<small>'+new Date().toLocaleTimeString()+'</small>'
    
            );
    
            //-------------------------------------------------
            // Object
            //-------------------------------------------------
    
            appState.set(
    
                'demo.person',
    
                {
    
                    first_name:first,
    
                    last_name:last,
    
                    age:
    
                        Math.floor(
    
                            20+
    
                            Math.random()*40
    
                        ),
    
                    gender:gender
    
                }
    
            );
    
        },1000);
    
    })();

    return {
        mount,
        unmount,
        init
    };

},{
    faces:['client']
}
);