__BORA_REGISTER_PLUGIN__('events.notifications', async function(scope){

    const realtime = await scope
        .getService('events.realtime');

    function mount(){

        realtime.on(
            'events.created',
            notifyCreated
        );
    }

    function unmount(){

        realtime.off(
            'events.created',
            notifyCreated
        );
    }

    function notifyCreated(event){

        alertBora.info(
            'New event available'
        );
    }

    return {
        mount,
        unmount
    };
});