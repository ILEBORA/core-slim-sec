__BORA_REGISTER_PLUGIN__('events.composer', async function(scope){

    const navigator = await scope
        .getService('navigator');

    function mount(){

        $(document).on(
            'click',
            '[data-action="event.compose"]',
            openComposer
        );
    }

    function unmount(){

        $(document).off(
            'click',
            '[data-action="event.compose"]',
            openComposer
        );
    }

    function openComposer(){

        navigator.go({
            route:'event.composer',
            surface:'popup'
        });
    }

    return {
        mount,
        unmount
    };
},{
    //requires:['realtime'],
    activateOn: (route) => route.startsWith('portal/events')
});