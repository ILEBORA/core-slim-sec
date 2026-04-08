__BORA_REGISTER_PLUGIN__('dom.reactivity', async function(scope){

    const $ = await scope.getService('jquery');
    const state = await scope.getService('state');

    function bindElement($el){

        const key   = $el.data('bind');
        const attr  = $el.data('bind-attr');
        const isHtml = $el.data('bind-html');

        if(!key) return;

        // Prevent duplicate bindings
        if($el.attr('data-bound')) return;
        $el.attr('data-bound', 'true');

        // -----------------------------
        // STATE → DOM
        // -----------------------------
        const unsub = state.subscribe(key, (value) => {

            // Attribute binding (e.g. src, href, etc.)
            if(attr){
                $el.attr(attr, value ?? '');
                return;
            }

            // HTML binding
            if(isHtml){
                $el.html(value ?? '');
                return;
            }

            // Input binding
            if($el.is('input, textarea, select')){
                if($el.val() !== value){
                    $el.val(value ?? '');
                }
            }
            // Default text binding
            else{
                $el.text(value ?? '');
            }

        }, true); // immediate fire

        // Store unsubscribe (future cleanup if needed)
        $el.data('unbind', unsub);

        // -----------------------------
        // DOM → STATE (two-way binding)
        // -----------------------------
        if($el.is('input, textarea, select')){
            $el.on('input.domreactivity change.domreactivity', function(){

                const newVal = $el.val();
                const current = state.get(key);

                // Avoid redundant updates
                if(newVal !== current){
                    state.set(key, newVal);
                }
            });
        }
    }

    // ---------------------------------
    // Mount (scoped for AJAX support)
    // ---------------------------------
    function mount(container = document){

        const $root = $(container);

        console.log('[DomReactivity] mounting...', $root);

        $root.find('[data-bind]').each(function(){
            bindElement($(this));
        });
    }

    // ---------------------------------
    // Optional cleanup (future-proofing)
    // ---------------------------------
    function destroy(container = document){

        const $root = $(container);

        $root.find('[data-bound]').each(function(){

            const $el = $(this);

            // Remove listener
            const unbind = $el.data('unbind');
            if(unbind) unbind();

            // Remove DOM listeners
            $el.off('.domreactivity');

            // Reset flags
            $el.removeAttr('data-bound');
            $el.removeData('unbind');
        });
    }

    return {
        mount,
        destroy
    };
});