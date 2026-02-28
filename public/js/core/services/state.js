__BORA_REGISTER_SERVICE__('state', function(scope){

    const store = {};
    const listeners = {};

    function get(key){
        return store[key];
    }

    function set(key, value){

        store[key] = value;

        if(listeners[key]){
            listeners[key].forEach(fn => {
                try { fn(value); }
                catch(e){ console.error('State listener failed', e); }
            });
        }

        scope.emit('state:' + key, value);
    }

    function subscribe(key, fn){
        listeners[key] ??= [];
        listeners[key].push(fn);
    }

    function update(key, updater){
        const current = store[key];
        const next = updater(current);
        set(key, next);
    }

    return {
        get,
        set,
        update,
        subscribe
    };
});