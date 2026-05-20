__BORA_REGISTER_PLUGIN__('events.attendees', async function(scope){

    const rsvp = await scope
        .getService('events.rsvp');

    function mount(){

        $(document).on(
            'click',
            '[data-action="event.attend"]',
            attend
        );

        $(document).on(
            'click',
            '[data-action="event.interested"]',
            interested
        );
    }

    function unmount(){

        $(document).off(
            'click',
            '[data-action="event.attend"]',
            attend
        );

        $(document).off(
            'click',
            '[data-action="event.interested"]',
            interested
        );
    }

    async function attend(){

        const id = $(this)
            .data('event-id');

        const response = await rsvp
            .attend(id);

        if(response.success){

            alertBora.success(
                'Attendance confirmed'
            );
        }
    }

    async function interested(){

        const id = $(this)
            .data('event-id');

        const response = await rsvp
            .interested(id);

        if(response.success){

            alertBora.success(
                'Marked interested'
            );
        }
    }

    return {
        mount,
        unmount
    };
},{
    requires:['realtime'],
    activateOn: (route) => route.startsWith('portal/events')
});