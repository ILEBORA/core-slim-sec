__BORA_REGISTER_SERVICE__('ui.actions', function(scope){

    const app = window.__BORA_APP__;

    /* ==================================================
       INTERNAL ACTION REGISTRY
    ================================================== */

    const actions = {};

    function register(name, fn){

        if(!name || typeof fn !== 'function'){
            console.warn('[ui.actions] Invalid register:', name);
            return;
        }

        if(actions[name]){
            console.warn(`[ui.actions] Overwriting action: ${name}`);
        }

        actions[name] = fn;
    }

    // function registerO(name, fn){
    //     if(!name || typeof fn !== 'function'){
    //         console.warn('[ui.actions] Invalid register:', name);
    //         return;
    //     }
    //     actions[name] = fn;
    // }

    function unregister(name, fn){

        if(!actions[name]) return;

        // 🔒 only remove if same function
        if(!fn || actions[name] === fn){
            delete actions[name];
        }
    }

    function run(name, el, event){
        const action = actions[name];

        if(!action){
            console.warn(`[ui.actions] Unknown action: ${name}`);
            return false;
        }

        try{
            console.log(`[ui.actions] '${name}' try...`);
            action(el, event);
        }
        catch(e){
            console.error(`[ui.actions] '${name}' failed`, e);
        }

        return true;
    }

    /* ==================================================
       HELPERS
    ================================================== */

    function parseJSONSafe(str){
        if (!str) return null;
        try { return JSON.parse(str); }
        catch(e){ return null; }
    }

    /* ==================================================
       CORE BINDING
    ================================================== */

    function bind(){
        console.log('navigation bind');
        document.addEventListener('click', async function(e){
            console.count(
                '[ui.actions] click handler'
            );
            /* ==================================================
               NEW SYSTEM — data-action
            ================================================== */

            const actionEl = e.target.closest('[data-action]');
            if (actionEl){

                e.preventDefault();

                const name = actionEl.dataset.action;
                // alert(name);
                // if(run(name, actionEl, e)){
                //     return;
                // }

                if(name){
                    const handled = run(name, actionEl, e);
                    if(handled) return;
                }
            }

            /* ==================================================
               BACKWARD COMPATIBILITY
            ================================================== */

            /* ---------- CONFIRM (runs BEFORE others) ---------- */

            const confirmEl = e.target.closest('[data-confirm]');
            if (confirmEl){

                const message = confirmEl.dataset.confirm || 'Are you sure?';

                if (!window.confirm(message)){
                    e.preventDefault();
                    return false;
                }
            }

            /* ---------- POPUP ---------- */

            const popupEl = e.target.closest('[data-popup]');
            if (popupEl){

                e.preventDefault();
                // alert('popup');
                const popup = await app?.plugin?.('popup');
                if (!popup) return;

                popup.open({
                    mode:   popupEl.dataset.mode || 'form',
                    module: popupEl.dataset.module,
                    group:  popupEl.dataset.group,
                    view:   popupEl.dataset.view,
                    id:     popupEl.dataset.id || null,
                    tab:    popupEl.dataset.tab || 'add',
                    size:   popupEl.dataset.size || 'md',
                    meta:   parseJSONSafe(popupEl.dataset.meta)
                });

                return;
            }

            /* ---------- NAVIGATION ---------- */

            const navEl = e.target.closest('[data-nav]');

            if (navEl){

                e.preventDefault();

                const navigation =
                    await app?.service?.('navigation');

                if (!navigation){
                    return;
                }

                const targetRoute =
                    navEl.dataset.nav;

                const currentRoute =
                    app.currentRoute
                        ? app.currentRoute()
                        : window.location.pathname;

                /* =========================
                SAME PAGE
                ========================= */
            
                const target = normalizeRoute(targetRoute);
                const current = normalizeRoute(currentRoute);

                if (
                    target.path === current.path &&
                    target.query === current.query
                ){
                    scope.emit?.(
                        'page.sameRoute',
                        {
                            route: targetRoute,
                            element: navEl
                        }
                    );

                    return;
                }

                navigation.go(targetRoute);

                return;
            }

            /* ---------- MENU REFRESH ---------- */

            const refreshEl = e.target.closest('[data-refresh-menu]');
            if (refreshEl){

                e.preventDefault();

                const menu = await app?.service?.('menu');
                if (!menu) return;

                const role = refreshEl.dataset.role;
                menu.refresh(role);

                return;
            }

            /* ==================================================
            LEGACY — data-e-click
            ================================================== */

            const eClickEl = e.target.closest('[data-e-click]');
            if (eClickEl){

                e.preventDefault();

                const expr = eClickEl.dataset.eClick;

                // 🔥 NEW: detect function-like vs action name
                if(expr.includes('(')){

                    try{
                        // ⚠️ controlled eval
                        const fn = new Function('event', 'el', `
                            return (${expr});
                        `);

                        fn(e, eClickEl);

                    }catch(err){
                        console.error('[ui.actions] inline execution failed:', expr, err);
                    }

                    return;
                }

                // fallback to action system
                if(run(expr, eClickEl, e)){
                    return;
                }
            }

        });
    }

    function normalizeRoute(route){

        const url = new URL(
            route,
            window.location.origin
        );

        return {
            path: url.pathname
                .replace(/\/+$/, ''),

            query: url.search
        };
    }

    function normalizeRouteO(route){

        if(!route){
            return '';
        }

        return String(route)
            .replace(/^\/+/, '')
            .replace(/\/+$/, '')
            .split('?')[0];

    }

    // function injectRefreshUI(navEl){

    //     if(
    //         document.querySelector(
    //             '#page_refresh'
    //         )
    //     ){
    //         return;
    //     }

    //     const div =
    //         document.createElement('div');

    //     div.id = 'page_refresh';

    //     div.setAttribute(
    //         'align',
    //         'center'
    //     );

    //     div.innerHTML = `
    //         <span
    //             class="jx"
    //             data-action="page.reload"
    //         >
    //             <abbr class="fa fa-refresh"></abbr>
    //             Refresh Page
    //         </span>
    //     `;

    //     document.body.appendChild(div);

    // }

    /* ==================================================
       INIT
    ================================================== */

    function init(){
        bind();
        console.log('[ui.actions] ready');
    }

    //
    async function withLoading(el, fn, onError){

        loading(el, true);

        try{
            return await fn();
        }
        catch(err){
            if(onError) onError(err);
            else console.error(err);
        }
        finally{
            loading(el, false);
        }
    }

    function loading(el, state = true, options = {}){

        const $el = window.jQuery ? window.jQuery(el) : null;

        if(!$el || $el.length === 0) return;

        const $btn = $el;
        const $text = $btn.find('.btn_text');
        const $loader = $btn.find('.btn_loading');

        const defaults = {
            loadingHTML: '<img class="jx_status" src="assets/images/icons/ajax.gif"/>',
            successHTML: '<img class="jx_status" src="assets/images/icons/success.png"/>',
            resetDelay: 0 // ms
        };

        const config = Object.assign({}, defaults, options);

        if(state === true){

            // store original text once
            if(!$btn.data('__original_text')){
                $btn.data('__original_text', $text.html());
            }

            $btn.prop('disabled', true);

            if($loader.length){
                $loader.html(config.loadingHTML);
            } else {
                // fallback if no loader span
                $btn.html(config.loadingHTML);
            }

        } else if(state === 'success'){

            if($loader.length){
                $loader.html(config.successHTML);
            }

            if(config.resetDelay > 0){
                setTimeout(() => loading(el, false, options), config.resetDelay);
            }

        } else {

            // reset
            $btn.prop('disabled', false);

            const original = $btn.data('__original_text');

            if($text.length && original){
                $text.html(original);
            }

            if($loader.length){
                $loader.html('');
            } else if(original){
                $btn.html(original);
            }

            $btn.removeData('__original_text');
        }
    }

    /* ==================================================
       PUBLIC API
    ================================================== */

    return {
        init,
        register,
        unregister,
        withLoading,
        loading,

        run   // optional, useful for manual triggering
    };
});