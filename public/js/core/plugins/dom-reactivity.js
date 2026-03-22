__BORA_REGISTER_PLUGIN__('DomReactivity', async function(scope){

    const jquery = await scope.getService('jquery');
    const state = await scope.getService('state');

    function mount(){
        console.log('[DomReactivity] mounted');
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

    return { mount };
});