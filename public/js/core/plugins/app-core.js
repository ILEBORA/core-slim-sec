__BORA_REGISTER_PLUGIN__(
    'AppCore',
    async function(scope){

        const hooks      = await scope.getService('hooks');
        const navigation = await scope.getService('navigation');
        const router     = await scope.getService('router');
        const logger     = await scope.getService('logger');
        const callbora   = await scope.getService('callbora');
        const preferences = await scope.getService('preferences');

        const config = scope.config || {};

        const state = {
            appPerms: null,
            curRole: null,
            SSE: null,
            _caps: {},
            _capWaiters: {}
        };

        function normalizeUrl(fullUrl){
            const base = window.__APP_BASE_PATH__ || '';

            if (!fullUrl) return '/';

            fullUrl = String(fullUrl);

            if (base && fullUrl.startsWith(base)){
                fullUrl = fullUrl.slice(base.length);
            }

            // remove query
            fullUrl = fullUrl.split('?')[0];

            // if (!fullUrl.startsWith('/')){
            //     fullUrl = '/' + fullUrl;
            // }

            return fullUrl || '';
        }

        /* =========================
           LIFECYCLE
        ========================= */

        async function mount(){
            console.log('[AppCore] mounted');
            await loadPermissions();

            await registerRouteGuards();

            await preferences.load();
            provide('preferences', preferences);

            /* =========================
            🔥 ROUTE → ACTIVATION BRIDGE
            ========================= */

            scope.on('route:changed', async (route) => {
                try{
                    await scope.evaluatePluginActivation(route);
                }catch(err){
                    console.error('[AppCore] Activation failed', err);
                }
            });

            // 🔥 Initial activation (after boot)
            // const initialRoute = normalizeUrl(window.location);
            // await scope.evaluatePluginActivation(initialRoute);

            if(config.dev){
                console.log('[AppCore] mounted');
            }

            scope.emit('app:initialized');
        }

        /* =========================
           PERMISSIONS
        ========================= */

        async function loadPermissions(){

            try{

                // if(typeof globalThis.acs === 'string' && acs.trim()){
                    state.appPerms = JSON.parse(rd('current_permissions'));
                // }

                // if(typeof globalThis.acsr === 'string' && acsr.trim()){
                    state.curRole = rd('current_role');
                // }
                if(config.dev){
                    console.log('PERMS::',state.appPerms);
                    console.log('ROLE::',state.curRole);
                    // alert('Perms');
                }

            }catch(e){
                console.error('[AppCore] Permission decode failed:', e);
            }
        }

        function hasPermission(perm, sub){
            console.log('PERMS::',state.appPerms);
            return state.appPerms?.[state.curRole]?.[perm]?.[sub] === true;
        }

        /* =========================
           ROUTE GUARDS
        ========================= */

        async function registerRouteGuards(){

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

            const result = await hooks.callAsyncUntilFalse('user.logout.request');
            console.log('RESULTS',result);

            // If ANY handler explicitly returns false → cancel
            if(result === false){
                return;
            }

            hooks.call('user.logout.before');
            
            // alert('Here logout');
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

                    // if(typeof globalThis.authChannel !== 'undefined'){
                    //     authChannel.postMessage({
                    //         cmd:'logout',
                    //         usr: globalThis.rd?.('bID')
                    //     });
                    // }
                })
                .setError((xhr) => console.error("Logout error:", xhr))
                .build();
        }

        async function logoutO(){
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