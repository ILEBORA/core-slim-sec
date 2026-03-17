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
        actions[name] = fn;
    }

    function run(name, el, event){
        const action = actions[name];

        if(!action){
            console.warn(`[ui.actions] Unknown action: ${name}`);
            return false;
        }

        try{
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

        document.addEventListener('click', function(e){

            /* ==================================================
               NEW SYSTEM — data-action
            ================================================== */

            const actionEl = e.target.closest('[data-action]');
            if (actionEl){

                e.preventDefault();

                const name = actionEl.dataset.action;

                if(run(name, actionEl, e)){
                    return;
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

                const popup = app?.service?.('popup');
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

                const navigation = app?.service?.('navigation');
                if (!navigation) return;

                navigation.go(navEl.dataset.nav);

                return;
            }

            /* ---------- MENU REFRESH ---------- */

            const refreshEl = e.target.closest('[data-refresh-menu]');
            if (refreshEl){

                e.preventDefault();

                const menu = app?.service?.('menu');
                if (!menu) return;

                const role = refreshEl.dataset.role;
                menu.refresh(role);

                return;
            }

        });
    }

    /* ==================================================
       INIT
    ================================================== */

    function init(){
        bind();
        console.log('[ui.actions] ready');
    }

    /* ==================================================
       PUBLIC API
    ================================================== */

    return {
        init,
        register,
        run   // optional, useful for manual triggering
    };
});