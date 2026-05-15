__BORA_REGISTER_SERVICE__('events.feed', async function(scope){

    const callbora = await scope
        .getService('callbora');

    async function load(options = {}){

        const response = await callbora.get(
            'api/modules/events/event/feed',
            options
        );

        return response?.data || [];
    }

    async function getById(id){

        return await callbora.get(
            `api/modules/events/event/get/${id}`
        );
    }

    async function search(q){

        return await callbora.get(
            'api/modules/events/search',
            { q }
        );
    }

    return {
        load,
        getById,
        search
    };
});