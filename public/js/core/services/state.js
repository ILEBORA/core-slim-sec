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

    // function bucket(name){

    //     stores[name] ??= {};
    //     listeners[name] ??= {};

    //     return {

    //         get(key){
    //             return stores[name][key];
    //         },

    //         set(key, value){

    //             stores[name][key] = value;

    //             listeners[name][key]?.forEach(fn => {
    //                 try {
    //                     fn(value);
    //                 } catch (e) {
    //                     console.error(
    //                         `State listener failed: ${name}.${key}`,
    //                         e
    //                     );
    //                 }
    //             });

    //             scope.emit(
    //                 `state:${name}:${key}`,
    //                 value
    //             );

    //             return value;
    //         },

    //         has(key){
    //             return key in stores[name];
    //         },

    //         remove(key){
    //             delete stores[name][key];
    //         },

    //         clear(){
    //             stores[name] = {};
    //         },

    //         update(key, updater){
    //             return this.set(
    //                 key,
    //                 updater(
    //                     this.get(key)
    //                 )
    //             );
    //         },

    //         subscribe(key, fn){
    //             listeners[name][key] ??= [];
    //             listeners[name][key].push(fn);
    //         }
    //     };
    // }

    return {
        get,
        set,
        update,
        subscribe,
        bucket,
        scope: bucket
    };
});