__BORA_REGISTER_SERVICE__('events.calendar', async function(scope){

    const callbora = await scope
        .getService('callbora');

    async function month(start, end){

        return await callbora.get(
            'api/modules/events/calendar/month',
            {
                start,
                end
            }
        );
    }

    async function week(start, end){

        return await callbora.get(
            'api/modules/events/calendar/week',
            {
                start,
                end
            }
        );
    }

    async function day(date){

        return await callbora.get(
            'api/modules/events/calendar/day',
            {
                date
            }
        );
    }

    return {
        month,
        week,
        day
    };
},{
    requires:['realtime'],
    activateOn: (route) => route.startsWith('portal/events/calendar')
});