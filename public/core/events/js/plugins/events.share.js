__BORA_REGISTER_PLUGIN__('events.share', async function(){

    function mount(){

        $(document).on(
            'click',
            '[data-action="event.share"]',
            share
        );
    }

    function unmount(){

        $(document).off(
            'click',
            '[data-action="event.share"]',
            share
        );
    }

    async function share(){

        const url = $(this)
            .data('url')
            || window.location.href;

        if(navigator.share){

            await navigator.share({
                url
            });

        } else {

            navigator.clipboard.writeText(url);

            alertBora.success(
                'Link copied'
            );
        }
    }

    return {
        mount,
        unmount
    };
});