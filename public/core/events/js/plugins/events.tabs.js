__BORA_REGISTER_PLUGIN__('events.tabs', async function(scope){

    const callbora = await scope.getService('callbora');

    async function resolve({ container, tab }) {

        const eventId =
            container.dataset.tabsId;

        return callbora.get(
            `api/modules/events/event/${eventId}/tabs/${tab}`
        );
    }

    return {
        resolve
    };
},{
    //requires:['realtime'],
    activateOn: (route) => route.startsWith('portal/events')
});