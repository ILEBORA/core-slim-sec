__BORA_REGISTER_SERVICE__('capability', function(scope){

    const registry = {};
    const waiters  = {};

    function provide(name, value){
        registry[name] = value;

        if(waiters[name]){
            waiters[name].forEach(fn => {
                try { fn(value); } catch(e){ console.error(e); }
            });
            delete waiters[name];
        }
    }

    function when(name, fn){

        if(registry[name]){
            fn(registry[name]);
            return;
        }

        if(!waiters[name]){
            waiters[name] = [];
        }

        waiters[name].push(fn);
    }

    return { provide, when };
});