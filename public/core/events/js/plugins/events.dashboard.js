__BORA_REGISTER_PLUGIN__('events.dashboard', async function(){

    function mount(){

        console.log(
            '[events.dashboard] mounted'
        );
    }

    function unmount(){

    }

    return {
        mount,
        unmount
    };
},{
    requires:['realtime'],
    activateOn: (route) => route.startsWith('portal/events')
});