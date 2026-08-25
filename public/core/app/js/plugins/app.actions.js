__BORA_REGISTER_PLUGIN__(
'app.actions',

async function(scope){

    const $ = await scope.getService('jquery');
    const appState = await scope.getService('state');
    const uiBindings = await  scope.getPlugin('ui.bindings');

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

        // alert('app actions mount');

        state.mounted = true;

        init();

        scan();

        (async function(){
            uiBindings.bind();
            const widgetImages = [
                'assets/images/widgets/1.jpg',
                'assets/images/widgets/2.jpg',
                'assets/images/widgets/3.jpg',
                'assets/images/widgets/4.jpg',
                'assets/images/widgets/5.jpg',
                'assets/images/widgets/6.jpg'
            ];

            setInterval(() => {
                console.log('suffle...');
                const shuffled = [...widgetImages].sort(() => Math.random() - 0.5);
                console.log(shuffled);
                appState.set('landing.impact.mainImage', shuffled[0]);
                appState.set('landing.impact.topImage', shuffled[1]);
                appState.set('landing.impact.bottomImage', shuffled[2]);

            }, 5000);
        });

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

}, { requires: ['jquery'] });