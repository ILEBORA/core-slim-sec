__BORA_REGISTER_SERVICE__('factbus', function(scope){

    const handlers = {};

    function on(type, fn){
        if(!handlers[type]) handlers[type] = [];
        handlers[type].push(fn);
    }

    function dispatch(type, payload){
        const fns = [
            ...(handlers['*'] || []),
            ...(handlers[type] || [])
        ];

        fns.forEach(fn=>{
            try{ fn(payload); }
            catch(e){ console.error('FactBus error', e); }
        });
    }

    const api = { on, dispatch };

    // 🔥 BACKWARD COMPATIBILITY
    window.FactBus = api;

    return api;

});