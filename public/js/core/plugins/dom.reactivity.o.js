__BORA_REGISTER_PLUGIN__('dom.reactivity', async function(scope){

    const $        = await scope.getService('jquery');
    const reactive = await scope.getPlugin('state.reactive');

    const { effect } = reactive;

    // 👇 assume store is globally shared (important!)
    const store = await scope.getService('store'); 
    // (you must expose this from content.manager or a central store plugin)

    // ----------------------------------------
    // 🔍 Resolve dot-path (e.g. "user.name")
    // ----------------------------------------
    function resolve(obj, path){
        return path.split('.').reduce((acc, key) => acc?.[key], obj);
    }

    function setValue(obj, path, value){
        const keys = path.split('.');
        const last = keys.pop();

        const target = keys.reduce((acc, key) => acc[key], obj);
        target[last] = value;
    }

    // ----------------------------------------
    // 🔗 Bind element
    // ----------------------------------------
    function bindElement($el){

        const key    = $el.data('bind');
        const attr   = $el.data('bind-attr');
        const isHtml = $el.data('bind-html');

        if(!key) return;
        if($el.attr('data-bound')) return;

        $el.attr('data-bound', 'true');

        // ----------------------------------------
        // 🔥 Reactive effect (auto tracking)
        // ----------------------------------------
        const runner = effect(() => {

            const value = resolve(store, key);

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
        });

        $el.data('effect', runner);

        // ----------------------------------------
        // 🔁 DOM → state
        // ----------------------------------------
        if($el.is('input, textarea, select')){
            $el.on('input.domreactivity change.domreactivity', function(){

                const newVal = $el.val();
                const current = resolve(store, key);

                if(newVal !== current){
                    setValue(store, key, newVal);
                }
            });
        }
    }

    // ----------------------------------------
    // 🧩 Mount
    // ----------------------------------------
    function mount(container = document){
        alert('mount');
        const $root = $(container);

        const $targets = $root.is('[data-bind]')
            ? $root.add($root.find('[data-bind]'))
            : $root.find('[data-bind]');

        $targets.each(function(){
            bindElement($(this));
        });
    }

    // ----------------------------------------
    // 🧹 Destroy
    // ----------------------------------------
    function destroy(container = document){

        const $root = $(container);

        $root.find('[data-bound]').each(function(){

            const $el = $(this);

            $el.off('.domreactivity');

            // ⚠️ No unsubscribe needed (effect auto-managed)
            $el.removeAttr('data-bound');
            $el.removeData('effect');
        });
    }

    // ----------------------------------------
    // 🔥 Lifecycle wiring
    // ----------------------------------------
    scope.on('view:mounted', ({root}) => {
        requestAnimationFrame(() => mount(root));
    });

    scope.on('view:destroyed', ({root}) => {
        destroy(root);
    });

    return { mount, destroy };
});