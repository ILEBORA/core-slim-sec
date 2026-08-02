__BORA_REGISTER_PLUGIN__('events.checkin', async function(scope){

    const rsvp = await scope
        .getService('events.rsvp');

    function mount(){

        $(document).on(
            'submit',
            '.event-checkin-form',
            submit
        );
    }

    function unmount(){

        $(document).off(
            'submit',
            '.event-checkin-form',
            submit
        );
    }

    async function submit(e){

        e.preventDefault();

        const form = this;

        const eventId = $(form)
            .data('event-id');

        const userId = $(form)
            .find('[name="user_id"]')
            .val();

        const response = await rsvp
            .checkin(eventId, userId);

        if(response.success){

            alertBora.success(
                'Check-in successful'
            );

        } else {

            alertBora.error(
                response.message || 'Failed'
            );
        }
    }

    return {
        mount,
        unmount
    };
},{
    //requires:['realtime'],
    activateOn: (route) => route.startsWith('portal/events')
});