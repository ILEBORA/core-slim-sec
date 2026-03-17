__BORA_REGISTER_PLUGIN__(
    'AppCore',
    function(scope){

        const hooks      = scope.getService('hooks');
        const navigation = scope.getService('navigation');
        const router     = scope.getService('router');
        const logger     = scope.getService('logger');
        const callbora   = scope.getService('callbora');
        const preferences = scope.getService('preferences');

        const config = scope.config || {};

        const state = {
            appPerms: null,
            curRole: null,
            SSE: null,
            _caps: {},
            _capWaiters: {}
        };

        /* =========================
           LIFECYCLE
        ========================= */

        async function mount(){
            loadPermissions();

            registerRouteGuards();

            await preferences.load();
            provide('preferences', preferences);

            if(config.dev){
                console.log('[AppCore] mounted');
            }

            scope.emit('app:initialized');
        }

        /* =========================
           PERMISSIONS
        ========================= */

        function loadPermissions(){

            try{

                if(typeof globalThis.acs === 'string' && acs.trim()){
                    state.appPerms = JSON.parse(atob(acs));
                }

                if(typeof globalThis.acsr === 'string' && acsr.trim()){
                    state.curRole = JSON.parse(atob(acsr));
                }

            }catch(e){
                console.error('[AppCore] Permission decode failed:', e);
            }
        }

        function hasPermission(perm, sub){
            return state.appPerms?.[state.curRole]?.[perm]?.[sub] === true;
        }

        /* =========================
           ROUTE GUARDS
        ========================= */

        function registerRouteGuards(){

            if(!router) return;

            router.beforeEach((to)=>{

                // Example guard: protect admin routes
                if(to.startsWith('/admin')){

                    const allowed = hasPermission('AppAccess', 'adminMode');

                    if(!allowed){
                        return { redirect:'/forbidden' };
                    }
                }

                return true;
            });
        }

        /* =========================
           LOGOUT
        ========================= */

        async function logout(){
            // Allow interception (e.g. confirmation UI)
            const proceed = await hooks.callAsync('user.logout.request');

            if(proceed === false){
                return;
            }

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

        function logoutO(){

            hooks?.call?.('user.logout.before');

            callbora
                .post("api/auth/logout", {})
                .then(()=>{

                    hooks?.call?.('user.logout.after');

                    navigation.go('');

                })
                .catch(err=>{
                    console.error('[AppCore] Logout failed', err);
                })
                .finally(()=>{

                    if(typeof globalThis.authChannel !== 'undefined'){
                        authChannel.postMessage({
                            cmd:'logout',
                            usr: globalThis.rd?.('bID')
                        });
                    }
                });
        }

        /* =========================
           SSE CONTROL
        ========================= */

        function pauseSSE(){
            state.SSE?.pause?.();
        }

        function resumeSSE(){
            state.SSE?.resume?.();
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

                state._capWaiters[cap].forEach(fn=>{
                    try{ fn(value); }
                    catch(e){
                        console.error(
                            `[Capability ${cap}] handler failed`,
                            e
                        );
                    }
                });

                delete state._capWaiters[cap];
            }
        }

        function when(cap, fn){

            if(state._caps.hasOwnProperty(cap)){
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
            mount,
            hasPermission,
            logout,
            pauseSSE,
            resumeSSE,
            setSSE,
            provide,
            when,
            getState: ()=>state
        };
    },
    {
        requires: ['hooks', 'navigation', 'router', 'callbora']
    }
);