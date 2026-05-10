__BORA_REGISTER_PLUGIN__(
'app.actions',

async function(scope){

    const state = {
        mounted:false,
        initialized:false,
        observer:null
    };

    /*
    |--------------------------------------------------------------------------
    | Mount
    |--------------------------------------------------------------------------
    */

    function mount(){

        if(state.mounted){
            return;
        }

        state.mounted = true;

        init();

        scan();

    }

    /*
    |--------------------------------------------------------------------------
    | Unmount
    |--------------------------------------------------------------------------
    */

    function unmount(){

        state.mounted = false;

    }

    /*
    |--------------------------------------------------------------------------
    | Init
    |--------------------------------------------------------------------------
    */

    function init(){

        if(state.initialized){
            return;
        }

        state.initialized = true;

        console.log(
            '[app.actions] mounted'
        );

        state.observer =
            new IntersectionObserver(

            (entries) => {

                entries.forEach((entry) => {

                    if(!entry.isIntersecting){
                        return;
                    }

                    const $el =
                        $(entry.target);

                    const animation =
                        $el.data(
                            'animation'
                        );

                    $el.addClass(
                        'in-view'
                    );

                    if(animation){

                        $el.addClass(
                            'animated ' +
                            animation
                        );

                    }

                    state.observer.unobserve(
                        entry.target
                    );

                });

            },
            {
                threshold:0.15,
                rootMargin:
                    '0px 0px -80px 0px'
            });

    }

    /*
    |--------------------------------------------------------------------------
    | Scan DOM
    |--------------------------------------------------------------------------
    */

    function scan(target = document){

        $(target)
        .find('.reveal')
        .each(function(){

            /*
            |--------------------------------------------------------------------------
            | Prevent duplicate observing
            |--------------------------------------------------------------------------
            */

            if(
                $(this).data(
                    'reveal-bound'
                )
            ){
                return;
            }

            $(this).data(
                'reveal-bound',
                true
            );

            state.observer.observe(
                this
            );

        });

    }

    /*
    |--------------------------------------------------------------------------
    | Public API
    |--------------------------------------------------------------------------
    */

    return {

        mount,
        unmount,
        scan

    };

});