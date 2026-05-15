__BORA_REGISTER_PLUGIN__('events.analytics', async function(){

    function mount(){

        initCharts();
    }

    function unmount(){

    }

    function initCharts(){

        console.log(
            '[events.analytics] charts init'
        );
    }

    return {
        mount,
        unmount
    };
});