__BORA_REGISTER_PLUGIN__('key.handlers', async function(scope){

    // const $ = await scope.getService('jquery');
    const config = await scope.config || {};

    const handlers = {};
    const context = {};

    const state = {
        mounted: false
    };  

    function mount(){
        if (state.mounted) return;
        state.mounted = true;

        console.log('[KeyHandlers] mounted');
        $(document).on('keydown.keyHandler', (event) => {

            const keyPressed = ucfirst(event.key); // keep your logic
            const modifiers = [];

            if (event.ctrlKey) modifiers.push('Control');
            if (event.shiftKey) modifiers.push('Shift');
            if (event.altKey) modifiers.push('Alt');

            const combo = [...modifiers, keyPressed].join('+');

            // Prevent default for specific combinations
            if (combo === 'Control+S' || combo === 'Control+G') {
                event.preventDefault();
            }

            if(handlers[combo]){

                handlers[combo].forEach(({ fn, ctx }) => {

                    if(context[ctx] === true || ctx === undefined){

                        const start = performance.now();
                        fn();
                        const end = performance.now();

                        if(config.dev){
                            console.log(`Executed ${combo} in ${end - start}ms`);
                        }

                        // Emit runtime-level event
                        scope.emit('key:' + combo);
                    }
                });
            }
        });

        if(config.dev){
            console.log('KeyHandlers initialized.');
        }
    }

    function unmount(){
        if (!state.mounted) return;
        state.mounted = false;  

        destroy();

        console.log('[KeyHandlers] unmounted');
    }

    function on(keys, fn, ctxName){

        if(typeof fn !== 'function'){
            console.warn('Key handler must be a function');
            return;
        }

        const combo = keys.join('+');

        handlers[combo] ??= [];
        handlers[combo].push({ fn, ctx: ctxName });
    }

    function setContext(name, value){
        context[name] = value;
    }

    function destroy(){
        $(document).off('keydown.keyHandler');
    }

    return {
        mount,
        unmount,
        on,
        setContext,
        destroy
    };
});