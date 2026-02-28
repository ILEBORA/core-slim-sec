__BORA_REGISTER_PLUGIN__('DomReactivity', function(scope){

    const $ = scope.getService('jquery');
    const state = scope.getService('state');

    function init(){

        $('[data-bind]').each(function(){

            const key = $(this).data('bind');
            const $el = $(this);

            state.subscribe(key, (value) => {

                if($el.is('input')){
                    $el.val(value);
                }
                else{
                    $el.text(value);
                }
            });

        });

    }

    return { init };
});