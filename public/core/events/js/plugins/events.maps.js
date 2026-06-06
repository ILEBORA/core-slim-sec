__BORA_REGISTER_PLUGIN__(
    'events.maps',
    async function(){

        function mount(){

            const maps =
                document.querySelectorAll(
                    '.event-map-picker'
                );

            maps.forEach(initMap);

        }

        function unmount(){

        }

        function initMap(el){

            if(el._mapInitialized){
                return;
            }

            el._mapInitialized = true;

            const form =
                el.closest('form');

            const latInput =
                form.querySelector(
                    '[name="latitude"]'
                );

            const lngInput =
                form.querySelector(
                    '[name="longitude"]'
                );

            const lat =
                parseFloat(latInput.value)
                || -1.2921;

            const lng =
                parseFloat(lngInput.value)
                || 36.8219;

            const map = L.map(el).setView(
                [lat, lng],
                13
            );

            L.tileLayer(
                "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",
                {
                    attribution:
                        "&copy; OpenStreetMap"
                }
            ).addTo(map);

            const marker = L.marker(
                [lat, lng],
                {
                    draggable: true
                }
            ).addTo(map);

            marker.on(
                'dragend',
                function(e){

                    const pos =
                        marker.getLatLng();

                    latInput.value =
                        pos.lat;

                    lngInput.value =
                        pos.lng;

                }
            );

            map.on(
                'click',
                function(e){

                    marker.setLatLng(
                        e.latlng
                    );

                    latInput.value =
                        e.latlng.lat;

                    lngInput.value =
                        e.latlng.lng;

                }
            );

        }

        return {
            mount,
            unmount,
            initMap
        };

}
,{
    requires:['realtime'],
    activateOn: (route) => route.startsWith('portal/events')
});