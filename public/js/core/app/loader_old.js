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
    const libs = new Set();

    const scriptCache = new Map(); // src -> Promise

    const progress = {
        total: 0,
        loaded: 0,
        failed: 0,
        active: false
    };

    function emitProgress(type, extra = {}){

        const app = global.__BORA_APP__;

        if(!app?.emit){
            return;
        }

        app.emit(type, {
            ...progress,
            percent:
                progress.total > 0
                    ? Math.round(
                        (progress.loaded + progress.failed)
                        / progress.total * 100
                    )
                    : 0,
            ...extra
        });

    }

    function beginLoading(total){

        progress.total = total;
        progress.loaded = 0;
        progress.failed = 0;
        progress.active = true;

        emitProgress('loader:start');

    }

    function waitForRegistration(name){

        const app = global.__BORA_APP__;

        if(app._getServices().has(name) || app._getPlugins().has(name)){
            return Promise.resolve();
        }

        return new Promise(resolve => {
            app._registrationWaiters.set(name, resolve);
        });
    }

    /* ==================================================
       UTIL: LOAD SCRIPT ONCE
    ================================================== */

    // Add version as a second parameter with a default fallback
    function loadScriptOnceN(src, version = '1.0.0') {

        // 1. Check cache with the original or modified src
        if(scriptCache.has(src)){
            return scriptCache.get(src);
        }

        const promise = new Promise((resolve, reject)=>{

            // 2. Append the version parameter to the URL
            const separator = src.includes('?') ? '&' : '?';
            const versionedSrc = `${src}${separator}v=${encodeURIComponent(version)}`;

            // 3. Prevent duplicate DOM injection using the original src 
            // (or use versionedSrc if you want to allow reloading different versions)
            if(document.querySelector(`script[src="${versionedSrc}"]`)){
                resolve(versionedSrc);
                return;
            }

            const script = document.createElement('script');
            script.src   = versionedSrc; // Use the versioned URL here
            script.async = true;
            script.dataset.bora = '1';

            script.onload = () => {
                resolve(versionedSrc);

                setTimeout(()=>{
                    script.remove();
                }, 0);
            };

            script.onerror = () => {
                reject(new Error(`[Loader] Failed to load script: ${versionedSrc}`));
            };

            document.head.appendChild(script);
        });

        scriptCache.set(src, promise);

        return promise;
    }

    async function loadScriptOnce(src, version = '1.0.0'){
        // console.log('[LOADER] loadScriptOnce',loadScriptOnce);
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

    function collectDependencies(name, set = new Set()){

        if(set.has(name)){
            return set;
        }

        set.add(name);

        const entry = manifest[name];

        if(entry?.requires){

            entry.requires.forEach(dep => {
                collectDependencies(dep, set);
            });

        }

        return set;

    }

    /* ==================================================
       CORE: ENSURE MODULE
    ================================================== */

    async function ensure(name, options = {}){

        progress.loaded++;

        emitProgress('loader:progress', {
            module:name
        });

        //

        const {
            stack = [],
            activate = true
        } = options;

        name = name.toLowerCase();

        // New
        const isRootCall = stack.length === 0;
        if(isRootCall){
            const deps = collectDependencies(name);
            beginLoading(deps.size);
        }
        //end new

        // console.warn(`[Loader-helper-new] Ensuring module: ${name}`);

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
        if(services?.has(name) || plugins?.has(name) || libs.has(name)){
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
                        // await ensure(dep, [...stack, name]);
                        await ensure(dep, {
                            stack:[...stack, name],
                            activate
                        });
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
                    // await app.integratePending();
                    await app.integratePending({
                        activate
                    });
                }

                // ✅ NEW: handle libs
                if(entry.type === 'lib'){
                    libs.add(name);
                    loaded.add(name);
                    return true;
                }

                /* ---------------------------
                   4. Validate Registration
                --------------------------- */

                if(!services.has(name) && !plugins.has(name)){
                    // console.warn(
                    //     `[Loader] Module "${name}" loaded but not registered.`
                    // );
                }

                

                loaded.add(name);

                if(global.__BORA_CONFIG__?.dev){
                    // console.log(`[Loader] Loaded: ${name}`);
                }

                return true;

            }catch(err){

                failed.set(name, err);
                // console.error(`[Loader] Failed: ${name}`, err);
                //
                progress.failed++;
                emitProgress('loader:error', {
                    module:name,
                    error:err
                });
                //

                throw err;

            }finally{
                loading.delete(name);

                if(
                    isRootCall &&
                    loading.size === 0
                ){

                    progress.active = false;

                    emitProgress(
                        'loader:complete'
                    );

                }
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

    async function script(src, globalName){

        await loadScriptOnce(src);

        if(globalName){

            await waitUntil(
                () => window[globalName]
            );

        }

        return window[globalName];
    
    }

    function waitUntil(predicate, timeout = 5000, interval = 20) {

        return new Promise((resolve, reject) => {
    
            const started = Date.now();
    
            const timer = setInterval(() => {
    
                if (predicate()) {
    
                    clearInterval(timer);
                    resolve(predicate());
    
                    return;
    
                }
    
                if (Date.now() - started > timeout) {
    
                    clearInterval(timer);
    
                    reject(
                        new Error('Timed out waiting.')
                    );
    
                }
    
            }, interval);
    
        });
    
    }

    /* ==================================================
       PUBLIC API
    ================================================== */

    const API = {
        ensure,
        preload,
        prefetch,
        status,

        script,
        waitUntil,

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