__BORA_REGISTER_PLUGIN__('ui.bindings', async function(scope){

    const $ = await scope.getService('jquery');
    const state = await scope.getService('state');

    function bindElement($el){
        const key   = $el.data('bind');
        const attr  = $el.data('bind-attr');
        const isHtml = $el.data('bind-html');

        if(!key) return;

        if($el.attr('data-bound')) return;
        $el.attr('data-bound', 'true');

        const unsub = state.subscribe(key, (value) => {

            const bindClass = $el.data('bind-class');

            if(bindClass){
                $el.toggleClass(bindClass, !!value);
            }

            if(attr){
                $el.attr(attr, value ?? '');
                return;
            }

            if(isHtml){
                $el.html(value ?? '');
                return;
            }

            if($el.is('input, textarea, select')){
                if($el.val() !== value){
                    $el.val(value ?? '');
                }
            } else {
                $el.text(value ?? '');
            }

        }, true);

        $el.data('unbind', unsub);

        if($el.is('input, textarea, select')){
            $el.on('input.domreactivity change.domreactivity', function(){
                const newVal = $el.val();
                const current = state.get(key);

                if(newVal !== current){
                    state.set(key, newVal);
                }
            });
        }
    }

    function mount(container = document){
        const $root = $(container);

        // $root.find('[data-bind]').each(function(){
        //     bindElement($(this));
        // });

        const $targets = $root.is('[data-bind]')
            ? $root.add($root.find('[data-bind]'))
            : $root.find('[data-bind]');

        $targets.each(function(){
            bindElement($(this));
        });
    }

    function destroy(container = document){
        const $root = $(container);

        $root.find('[data-bound]').each(function(){

            const $el = $(this);

            const unbind = $el.data('unbind');
            if(unbind) unbind();

            $el.off('.domreactivity');

            $el.removeAttr('data-bound');
            $el.removeData('unbind');
        });
    }

    function autoBind(){
        scope.on('view:mounted', ({root}) => {
            mount(root);
        });
    }

    return {
        mount,
        destroy,
        autoBind
    };
});