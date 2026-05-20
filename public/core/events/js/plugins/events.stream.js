__BORA_REGISTER_PLUGIN__('events.stream', async function(scope){

    const realtime = await scope
        .getService('events.realtime');

    function mount(){

        realtime.on(
            'events.created',
            handleCreated
        );
    }

    function unmount(){

        realtime.off(
            'events.created',
            handleCreated
        );
    }

    function handleCreated(event){

        console.log(
            '[events.stream]',
            event
        );
    }

    return {
        mount,
        unmount
    };
},{
    requires:['realtime'],
    activateOn: (route) => route.startsWith('portal/events')
});