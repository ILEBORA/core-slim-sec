__BORA_REGISTER_PLUGIN__('events.calendar.ui', async function(scope){

    const calendar = await scope
        .getService('events.calendar');

    async function mount(){

        const el = document.querySelector(
            '.events-calendar'
        );

        if(!el) return;

        console.log(
            '[events.calendar.ui] mounted'
        );
    }

    function unmount(){

    }

    return {
        mount,
        unmount
    };
});