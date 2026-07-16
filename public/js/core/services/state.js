__BORA_REGISTER_SERVICE__('state', function(scope){

    const store = {};
    const listeners = {};

    const buckets = {};
    const bucketListeners = {};

    function get(key){
        return store[key];
    }

    function set(key, value){

        store[key] = value;

        notify(key, value);

        // if(listeners[key]){
        //     listeners[key].forEach(fn => {
        //         try { fn(value); }
        //         catch(e){ console.error('State listener failed', e); }
        //     });
        // }

        if(
            value &&
            typeof value === 'object'
        ){
            bubble(key, value);
        }

        // scope.emit('state:' + key, value);
    }

    function notify(key, value){

        listeners[key]?.forEach(fn => {
            try{
                fn(value);
            }catch(e){
                console.error('State listener failed', e);
            }
        });
    
        scope.emit('state:' + key, value);
    }

    function bubble(base, obj){

        Object.entries(obj).forEach(([key, value]) => {
    
            const path = `${base}.${key}`;
    
            if(listeners[path]){
                notify(path, value);
            }
    
            if(
                value &&
                typeof value === 'object'
            ){
                bubble(path, value);
            }
    
        });
    
    }

    function merge(key, patch){

        const current =
            structuredClone(
                store[key] ?? {}
            );
    
        deepMerge(
            current,
            patch
        );
    
        set(
            key,
            current
        );
    
        return current;
    }
    
    function deepMerge(target, source){
    
        if(!source){
            return target;
        }
    
        Object.entries(source).forEach(([key, value])=>{
    
            if(
                value &&
                typeof value === 'object' &&
                !Array.isArray(value)
            ){
    
                target[key] ??= {};
    
                deepMerge(
                    target[key],
                    value
                );
    
            }else{
    
                target[key] = value;
    
            }
    
        });
    
        return target;
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

    function bucket(name){

        buckets[name] ??= {};
        bucketListeners[name] ??= {};

        return {

            get(key){
                return buckets[name][key];
            },

            set(key, value){

                buckets[name][key] = value;

                bucketListeners[name][key]
                    ?.forEach(fn => {
                        try {
                            fn(value);
                        } catch (e) {
                            console.error(
                                `State listener failed: ${name}.${key}`,
                                e
                            );
                        }
                    });

                scope.emit(
                    `state:${name}:${key}`,
                    value
                );

                return value;
            },

            has(key){
                return key in buckets[name];
            },

            remove(key){
                delete buckets[name][key];
            },

            clear(){
                buckets[name] = {};
            },

            update(key, updater){
                return this.set(
                    key,
                    updater(
                        this.get(key)
                    )
                );
            },

            subscribe(key, fn){
                bucketListeners[name][key] ??= [];
                bucketListeners[name][key].push(fn);
            }
        };
    }


    return {
        get,
        set,
        update,
        merge,
        subscribe,
        bucket,
        scope: bucket
    };
});