__BORA_REGISTER_PLUGIN__('state.reactive', async function(scope){

    const targetMap = new WeakMap();
    let activeEffect = null;

    // ----------------------------------------
    // 🧠 Track dependencies
    // ----------------------------------------
    function track(target, key){
        if(!activeEffect) return;

        let depsMap = targetMap.get(target);
        if(!depsMap){
            depsMap = new Map();
            targetMap.set(target, depsMap);
        }

        let dep = depsMap.get(key);
        if(!dep){
            dep = new Set();
            depsMap.set(key, dep);
        }

        dep.add(activeEffect);
    }

    // ----------------------------------------
    // 🔥 Trigger updates
    // ----------------------------------------
    function trigger(target, key){
        const depsMap = targetMap.get(target);
        if(!depsMap) return;

        const dep = depsMap.get(key);
        if(dep){
            dep.forEach(effect => queueJob(effect));
        }
    }

    // ----------------------------------------
    // ⚡ Job queue (batch updates)
    // ----------------------------------------
    const jobQueue = new Set();
    let isFlushing = false;

    function queueJob(job){
        jobQueue.add(job);

        if(!isFlushing){
            isFlushing = true;
            Promise.resolve().then(flushJobs);
        }
    }

    function flushJobs(){
        jobQueue.forEach(job => job());
        jobQueue.clear();
        isFlushing = false;
    }

    // ----------------------------------------
    // 🧬 reactive()
    // ----------------------------------------
    function reactive(target){
        return new Proxy(target, {
            get(obj, key){
                track(obj, key);
                return obj[key];
            },
            set(obj, key, value){
                const old = obj[key];
                obj[key] = value;

                if(old !== value){
                    trigger(obj, key);
                }

                return true;
            }
        });
    }

    // ----------------------------------------
    // ⚙️ effect()
    // ----------------------------------------
    function effect(fn){
        const effectFn = () => {
            activeEffect = effectFn;
            fn();
            activeEffect = null;
        };

        effectFn();
        return effectFn;
    }

    // ----------------------------------------
    // 🧮 computed()
    // ----------------------------------------
    function computed(getter){
        let value;
        let dirty = true;

        const runner = effect(() => {
            value = getter();
            dirty = false;
        });

        return {
            get value(){
                if(dirty){
                    runner();
                }
                return value;
            }
        };
    }

    return {
        reactive,
        effect,
        computed
    };
});