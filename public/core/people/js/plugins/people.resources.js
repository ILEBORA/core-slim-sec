__BORA_REGISTER_PLUGIN__(
    'people.resources',
    async function(scope){

        const resources = await scope.getService('resources');
        const appState = await scope.getService('state');
        const bindings = await scope.getPlugin( 'ui.bindings');
        
        const peopleState = appState.bucket('person');

        const callbora = await scope.getService('callbora');

        const state = {
            initialized:false,
            mounted:false
        };

        function mount(){

            if(state.mounted){
                return;
            }
            // alert('People resources mounted');
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
    
        function init(){

            if(state.initialized){
                return;
            }
    
            state.initialized = true;
    
            registerListeners();
    
        }


        function registerListeners(){
            scope.on('view:mounted', ({ root }) => {
                // alert('view mounted');
                bindings.mount(root);
            });
            
            scope.on('view:destroyed', ({ root }) => {
                bindings.destroy(root);
            });
    
            resources.register(
                'people',
                async () => {
    
                    const res =
                        await callbora.get(
                            'api/modules/people/dictionary'
                        );
    
                    return res.data;
                }
            );
    
            resources.project(
    
                'people',
            
                event => {
                    console.log(
                        '[PROJECTOR]',
                        event
                    );
    
                    // const p = event[0];
                    // console.log('[EVENT]',p);
    
                    // peopleState.set(
                    //     p.id,
                    //     p
                    // );

                    if(!event){
                        console.warn('Event is undefined'); 
                        return;
                    }

                    if(!event.action){
                        console.warn('Event has no action');
                        return;
                    }
    
                    
            
                    switch (event.action) {
            
                        case 'created':
                        case 'updated':
            
                            event.items.forEach(person => {

                                // console.log(
                                //     '[PERSON STATE]',
                                //     peopleState.get(
                                //         person.id
                                //     )
                                // );
    
                                // console.log(
                                //     'SETTING',
                                //     person.id
                                // );
                                
    
                                // peopleState.set(
                                //     person.id,
                                //     person
                                // );

                                appState.merge(
                    
                                    `person.${person.id}`,
                        
                                    person
                        
                                );

                                // console.log(`person.${person.id} was updated...`);
            
                            });
            
                            break;
            
                        case 'deleted':
            
                            event.items.forEach(person => {
            
                                peopleState.remove(
                                    person.id
                                );
            
                            });
            
                            break;
                    }
            
                }
            
            );
    

            
    
            /*
            |--------------------------------------------------------------------------
            | Person Added
            |--------------------------------------------------------------------------
            */
    
            scope.on(
    
                'people.added',
            
                ({ person }) => {
                    
                    resources.patch(
            
                        'people',
            
                        null,
            
                        people => {
            
                            people.push(person);
            
                            people.sort(
                                (a, b) =>
                                    a.full_name.localeCompare(
                                        b.full_name
                                    )
                            );
            
                            return {
            
                                data: people,
            
                                operation: {
            
                                    action: 'created',
            
                                    items: [person]
            
                                }
            
                            };
            
                        }
            
                    );
            
                }
            
            );
    
            /*
            |--------------------------------------------------------------------------
            | Person Updated
            |--------------------------------------------------------------------------
            */
    
            scope.on(
    
                'people.updated',
            
                ({ person }) => {
    
                    console.log(
                        '[PEOPLE.UPDATED]',
                        person
                    );
    
                    console.log(resources);
                    console.log(typeof resources.patch);
            
                    resources.patch(
            
                        'people',
            
                        null,
            
                        people => {
            
                            const existing =
                                people.find(
                                    p =>
                                        p.id ==
                                        person.id
                                );
            
                            if (!existing) {
                                return {
                                    data: people
                                };
                            }
            
                            Object.assign(
                                existing,
                                person
                            );
    
                            console.log('PEEK',existing);
            
                            return {
            
                                data: people,
            
                                operation: {
            
                                    action: 'updated',
            
                                    items: [existing]
            
                                }
            
                            };
            
                        }
            
                    );
                    // console.log('5 after patch');
                    // console.log('PEEK',
                    //     resources.peek(
                    //         'people'
                    //     )
                    // );
            
                }
            
            );
    
            /*
            |--------------------------------------------------------------------------
            | Person Deleted
            |--------------------------------------------------------------------------
            */
    
            scope.on(
    
                'people.deleted',
            
                ({ personId }) => {
            
                    resources.patch(
            
                        'people',
            
                        null,
            
                        people => {
            
                            const removed =
                                people.find(
                                    p =>
                                        p.id ==
                                        personId
                                );
            
                            return {
            
                                data:
                                    people.filter(
                                        p =>
                                            p.id !=
                                            personId
                                    ),
            
                                operation: {
            
                                    action: 'deleted',
            
                                    items:
                                        removed
                                            ? [removed]
                                            : []
            
                                }
            
                            };
            
                        }
            
                    );
            
                }
            
            );

            //Presence
            resources.register(
                'presence',
                async () => {
            
                    const res = await callbora.get(
                        'api/modules/people/presences'
                    );
            
                    return res.data;
                }
            );

            resources.project(

                'presence',
            
                event => {
                    console.log('[PRESENCE EVENT]',event);
                    if(event){
                        event.forEach(presence => {
                            // console.log(
                            //     '[PRESENCE]'.
                            //     resources.peek(
                            //         `people`,
                            //         event.personId
                            //     )
                            // );
                            appState.merge(
                
                                `person.${event.personId}`,
                
                                presence.personId,
                
                                {
                                    presence
                                }
                
                            );
                
                        });
                    }
            
                }
            
            );

            scope.on(
                'person.presence',
                payload => {
                    const event = payload.event;
                    console.log('[EVENT]', event);
                    // alert(event.personId);
                    // const person =
                    //     appState.get(
                    //         `person.${event.personId}`
                    //     );
                    
                    // if(!person){
                    //     alert(`Person ${event.personId} not found`);
                    //     return;
                    // }

                    // console.log('[EVENT person]', person);
            
                    // person.presence = {
            
                    //     status:event.status,
            
                    //     lastSeen:event.lastSeen
            
                    // };

                    // console.log('[EVENT person]', person);
            
            
                    appState.merge(
                        `person.${event.personId}`,
                        {
                            presence:{
                                status:event.status,
                                timestamp:event.timestamp
                            }
                        }
                    );
            
                }
            );

            bindings.renderer(
                'presence-dot',
                (el, presence) => {
            
                    el.classList.remove(
                        'online',
                        'offline',
                        'away'
                    );
            
                    if(!presence){
                        return;
                    }
            
                    el.classList.add(
                        presence.status
                    );
                }
            );
            
            bindings.renderer(
                'presence-text',
                (el, presence) => {
            
                    if(!presence){
                        el.textContent = '';
                        return;
                    }
            
                    if(presence.status === 'online'){
                        el.textContent = 'Online';
                        return;
                    }
            
                    el.textContent =
                        'Last seen ' +
                        timeAgo(presence.timestamp);
            
                }
            );

            resources.get('presence');
        }

        function timeAgo(timestamp){

            const diff =
                Date.now() -
                new Date(timestamp).getTime();
        
            const mins =
                Math.floor(diff / 60000);
        
            if(mins < 1){
                return 'just now';
            }
        
            if(mins < 60){
                return `${mins} min ago`;
            }
        
            const hrs =
                Math.floor(mins / 60);
        
            if(hrs < 24){
                return `${hrs} hr${hrs > 1 ? 's' : ''} ago`;
            }
        
            const days =
                Math.floor(hrs / 24);
        
            return `${days} day${days > 1 ? 's' : ''} ago`;
        
        }
        
        
        
        //End

        return{
            mount,
            unmount
        };
    }
);