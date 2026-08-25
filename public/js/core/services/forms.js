__BORA_REGISTER_SERVICE__('forms', async function(scope){

    const journeys = {};

    let bound = false;
    let submitHandler = null;

    function register(name, fn){

        if(!name || typeof fn !== 'function'){
            console.warn('[form.journey] Invalid journey:', name);
            return;
        }

        if(journeys[name]){
            console.warn(`[form.journey] Overwriting journey: ${name}`);
        }

        journeys[name] = fn;
    }

    function unregister(name){
        delete journeys[name];
    }

    function get(name){
        return journeys[name] || null;
    }

    function beforeSubmit($form){

        if(typeof appHooks === 'undefined'){
            return true;
        }

        return appHooks.callHook('form:beforeSubmit', $form) !== false;
    }

    function afterSubmit($form, resp){

        if(typeof appHooks !== 'undefined'){
            appHooks.callHook('form:afterSubmit', $form, resp);
        }
    }

    function defaultJourney($form, done){
        alert('defaultJourney');
        $.ajax({
            url: $form.attr('action'),
            method: $form.attr('method') || 'POST',
            data: $form.serialize(),

            success(resp){
                done?.(resp);
            },

            error(xhr){

                let resp = xhr.responseJSON;

                if(!resp && xhr.responseText){
                    try{
                        resp = JSON.parse(xhr.responseText);
                    }
                    catch{
                        resp = {
                            success:false,
                            message:'Unknown server error'
                        };
                    }
                }

                done?.(resp);
            }
        });
    }

    function run(name, $form, done){

        const handler = journeys[name] || defaultJourney;

        if(!beforeSubmit($form)){
            return false;
        }

        $form.data('journey-running', true);

        handler($form, function(resp){

            afterSubmit($form, resp);

            $form.removeData('journey-running');

            done?.(resp);
        });

        return true;
    }

    function bind(){

        if(bound) return;
        // alert('forms bound');

        bound = true;

        submitHandler = function(e){

            const $form = $(this);

            if($form.data('journey-running')){
                e.preventDefault();
                return;
            }

            e.preventDefault();

            const journey =
                $form.data('handler') || 'default';

            run(journey, $form);
        };

        $(document)
            .off('submit.formJourney')
            .on(
                'submit.formJourney',
                'form[data-ajax="true"]',
                submitHandler
            );

        console.log('[form.journey] bound');
    }

    function unbind(){

        if(!bound) return;

        $(document).off(
            'submit.formJourney',
            submitHandler
        );

        bound = false;
        submitHandler = null;
    }

    function init(){
        bind();
        console.log('[form.journey] ready');
    }

    init();

    return {
        autoStart: true,
        init,

        bind,
        unbind,

        register,
        unregister,
        get,

        run,

        default: defaultJourney

    };

});

// alert('forms');