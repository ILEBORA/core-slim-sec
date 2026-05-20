__BORA_REGISTER_SERVICE__(
'events.calendar',
async function(scope){

    const callbora =
        await scope.getService(
            'callbora'
        );

    async function load(
        view,
        params = {}
    ){

        return await callbora.get(

            `api/modules/events/calendar/${view}`,

            params
        );
    }

    return {
        load
    };
});