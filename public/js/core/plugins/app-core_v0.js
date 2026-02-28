__BORA_REGISTER_PLUGIN__('AppCore', function(scope){

    const hooks = scope.getService('hooks');
    const config = scope.config || {};

    const state = {
        appPerms: null,
        curRole: null,
        SSE: null,
        _caps: {},
        _capWaiters: {}
    };

    /* =========================
       INIT
    ========================= */

    function init(){
        loadPermissions();

        if(config.dev){
            console.log('AppCore initialized.');
        }

        scope.emit('app:initialized');
    }

    /* =========================
       PERMISSIONS
    ========================= */

    function loadPermissions(){
        try{
            if(typeof acs !== 'undefined' && acs.trim() !== ''){
                state.appPerms = JSON.parse(atob(acs));
            }
            if(typeof acsr !== 'undefined' && acsr.trim() !== ''){
                state.curRole = JSON.parse(atob(acsr));
            }
        }
        catch(e){
            console.error('Permission decode failed:', e);
        }
    }

    function hasPermission(perm, sub){
        return state.appPerms?.[state.curRole]?.[perm]?.[sub] === true;
    }

    /* =========================
       LOGOUT
    ========================= */

    function logout(){

        hooks.call('user.logout.before');

        new CallBora("api/auth/logout")
            .setMethod("POST")
            .setParams({})
            .setCallback(() => {
                hooks.call('user.logout.after');
                redirectTo('', true);
            })
            .setDone(() => {
                if(typeof authChannel !== 'undefined'){
                    authChannel.postMessage({cmd:'logout', usr: rd('bID')});
                }
            })
            .setError((xhr) => console.error("Logout error:", xhr))
            .build();
    }

    /* =========================
       SSE CONTROL
    ========================= */

    function pauseSSE(){
        if(state.SSE){
            state.SSE.pause();
        }
    }

    function resumeSSE(){
        if(state.SSE){
            state.SSE.resume();
        }
    }

    function setSSE(instance){
        state.SSE = instance;
    }

    /* =========================
       CAPABILITY SYSTEM
    ========================= */

    function provide(cap, value){

        state._caps[cap] = value;

        if(state._capWaiters[cap]){
            state._capWaiters[cap].forEach(fn => {
                try { fn(value); }
                catch(e){ console.error(`Capability '${cap}' failed`, e); }
            });

            delete state._capWaiters[cap];
        }
    }

    function when(cap, fn){

        if(state._caps[cap]){
            fn(state._caps[cap]);
            return;
        }

        state._capWaiters[cap] ??= [];
        state._capWaiters[cap].push(fn);
    }

    /* =========================
       PUBLIC API
    ========================= */

    return {
        init,
        hasPermission,
        logout,
        pauseSSE,
        resumeSSE,
        setSSE,
        provide,
        when,
        get state(){ return state; }
    };
});