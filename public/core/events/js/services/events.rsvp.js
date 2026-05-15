__BORA_REGISTER_SERVICE__('events.rsvp', async function(scope){

    const callbora = await scope
        .getService('callbora');

    async function attend(eventId){

        return await callbora.post(
            'api/modules/events/attendee/rsvp',
            {
                event_id:eventId,
                status:'going'
            }
        );
    }

    async function interested(eventId){

        return await callbora.post(
            'api/modules/events/attendee/rsvp',
            {
                event_id:eventId,
                status:'interested'
            }
        );
    }

    async function decline(eventId){

        return await callbora.post(
            'api/modules/events/attendee/rsvp',
            {
                event_id:eventId,
                status:'declined'
            }
        );
    }

    async function checkin(eventId, userId){

        return await callbora.post(
            'api/modules/events/attendee/checkin',
            {
                event_id:eventId,
                user_id:userId
            }
        );
    }

    return {
        attend,
        interested,
        decline,
        checkin
    };
});