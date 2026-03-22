/**
 * BoraCore Loader
 * ----------------------------------------
 * Responsibilities:
 * - Resolve dependencies from manifest
 * - Dynamically load scripts (once)
 * - Deduplicate concurrent loads
 * - Integrate with BoraRuntime registration pipeline
 * - Provide preload capability
 */

(function(global){

    'use strict';

    /* ==================================================
       INTERNAL STATE
    ================================================== */

    const manifest = global.__BORA_MANIFEST__ || {};

    const loading  = new Map();   // name -> Promise
    const loaded   = new Set();   // name
    const failed   = new Map();   // name -> error

    const scriptCache = new Map(); // src -> Promise

    /* ==================================================
       UTIL: LOAD SCRIPT ONCE
    ================================================== */

    function loadScriptOnce(src){

        if(scriptCache.has(src)){
            return scriptCache.get(src);
        }

        const promise = new Promise((resolve, reject)=>{

            // prevent duplicate DOM injection
            if(document.querySelector(`script[src="${src}"]`)){
                resolve(src);
                return;
            }

            const script = document.createElement('script');
            script.src   = src;
            script.async = true;
            script.dataset.bora = '1';

            script.onload = () => {
                resolve(src);

                // 🔥 CRITICAL
                // global.__BORA_APP__?.integratePending();
                // global.__BORA_APP__?.integratePending()?.catch(console.error);

                // remove AFTER integration (safe)
                setTimeout(()=>{
                    script.remove();
                }, 0);

                resolve(src);
            };

            script.onerror = () => {
                reject(new Error(`[Loader] Failed to load script: ${src}`));
            };

            document.head.appendChild(script);
        });

        scriptCache.set(src, promise);

        return promise;
    }

    /* ==================================================
       CORE: ENSURE MODULE
    ================================================== */

    async function ensure(name, stack = []){

        name = name.toLowerCase();

        if(stack.includes(name)){
            const cycle = [...stack, name].join(' → ');
            const err = new Error(`[Loader] Circular dependency detected: ${cycle}`);
            failed.set(name, err);
            throw err;
        }

        if(name === 'runtime'){
            return; // skip registration expectation
        }
            
        const app = global.__BORA_APP__;

        if(!app){
            throw new Error('[Loader] __BORA_APP__ not initialized');
        }

        const services = app._getServices?.();
        const plugins  = app._getPlugins?.();

        // already registered
        if(services?.has(name) || plugins?.has(name)){
            loaded.add(name);
            return true;
        }

        // already resolved
        if(loaded.has(name)){
            return true;
        }

        // failed previously
        if(failed.has(name)){
            throw failed.get(name);
        }

        // already loading
        if(loading.has(name)){
            return loading.get(name);
        }

        const entry = manifest[name];

        if(!entry){
            const err = new Error(`[Loader] Unknown module: ${name}`);
            failed.set(name, err);
            throw err;
            // return false;
        }

        const promise = (async ()=>{

            try{

                /* ---------------------------
                   1. Resolve Dependencies
                --------------------------- */

                if(entry.requires && entry.requires.length){

                    for(const dep of entry.requires){
                        await ensure(dep, [...stack, name]);
                    }

                }

                /* ---------------------------
                   2. Load Script
                --------------------------- */

                if(entry.file && entry.file !== '__inline__'){

                    await loadScriptOnce(entry.file);

                }

                /* ---------------------------
                   3. Integrate into Runtime
                --------------------------- */

                if(typeof app.integratePending === 'function'){
                    app.integratePending();
                }

                /* ---------------------------
                   4. Validate Registration
                --------------------------- */

                if(!services.has(name) && !plugins.has(name)){
                    console.warn(
                        `[Loader] Module "${name}" loaded but not registered.`
                    );
                }

                loaded.add(name);

                if(global.__BORA_CONFIG__?.dev){
                    console.log(`[Loader] Loaded: ${name}`);
                }

                return true;

            }catch(err){

                failed.set(name, err);
                console.error(`[Loader] Failed: ${name}`, err);
                throw err;

            }finally{
                loading.delete(name);
            }

        })();

        loading.set(name, promise);

        return promise;
    }

    /* ==================================================
       PRELOAD
    ================================================== */

    function preload(list = []){

        if(!Array.isArray(list)){
            list = [list];
        }

        return Promise.all(list.map(name => ensure(name)));

    }

    /* ==================================================
       OPTIONAL: PREFETCH (NON-BLOCKING)
    ================================================== */

    function prefetch(list = []){

        if(!Array.isArray(list)){
            list = [list];
        }

        list.forEach(async name => {
            await ensure(name).catch(()=>{});
        });

    }

    /* ==================================================
       DEBUG / INSPECTION
    ================================================== */

    function status(){

        return {
            loaded: Array.from(loaded),
            loading: Array.from(loading.keys()),
            failed: Array.from(failed.keys())
        };

    }

    /* ==================================================
       PUBLIC API
    ================================================== */

    const API = {
        ensure,
        preload,
        prefetch,
        status,

        // internal (debug)
        _manifest: manifest,
        _loading: loading,
        _loaded: loaded,
        _failed: failed
    };

    /* ==================================================
       EXPORT
    ================================================== */

    global.__BORA_LOADER__ = API;

})(window);