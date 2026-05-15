__BORA_REGISTER_PLUGIN__('events.maps', async function(){

    function mount(){

        const maps = document.querySelectorAll(
            '.event-location-map'
        );

        maps.forEach(initMap);
    }

    function unmount(){

    }

    function initMap(el){

        const lat = el.dataset.lat;
        const lng = el.dataset.lng;

        console.log(
            '[events.maps]',
            lat,
            lng
        );

        // TODO :: Leaflet / Google Maps
    }

    return {
        mount,
        unmount
    };
});