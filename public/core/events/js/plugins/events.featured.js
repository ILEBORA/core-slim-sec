__BORA_REGISTER_PLUGIN__('events.featured', async function(){

    function mount(){
        // alert('featured mount');
        if(typeof Swiper === 'undefined') return;

        const el = document.querySelector(
            '.featured-events-slider'
        );

        if(!el) return;

        new Swiper(el, {
            slidesPerView:1.2,
            spaceBetween:16,
            breakpoints:{
                768:{
                    slidesPerView:2
                },
                1200:{
                    slidesPerView:3
                }
            }
        });
    }

    function unmount(){

    }

    return {
        mount,
        unmount
    };
},{
    requires:['realtime'],
    activateOn: (route) => route.startsWith('portal/events/featured')
});