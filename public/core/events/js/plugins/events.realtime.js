__BORA_REGISTER_SERVICE__('events.realtime', async function(scope){

    const sse = await scope
        .getService('realtime.sse');

    function on(event, callback){

        sse.on(event, callback);
    }

    function off(event, callback){

        sse.off(event, callback);
    }

    return {
        on,
        off
    };
});