__BORA_REGISTER_SERVICE__('ui.actions', function(scope){

    const app = window.__BORA_APP__;

    function parseJSONSafe(str){
        if (!str) return null;
        try { return JSON.parse(str); }
        catch(e){ return null; }
    }

    function bind(){
        document.addEventListener('click', function(e){

            /* ==================================================
               POPUP TRIGGER
               data-popup
            ================================================== */

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

            /* ==================================================
               SPA NAVIGATION
               data-nav="/route"
            ================================================== */

            const navEl = e.target.closest('[data-nav]');
            if (navEl){

                e.preventDefault();

                const navigation = app?.service?.('navigation');
                if (!navigation) return;

                navigation.go(navEl.dataset.nav);

                return;
            }

            /* ==================================================
               MENU REFRESH
               data-refresh-menu
            ================================================== */

            const refreshEl = e.target.closest('[data-refresh-menu]');
            if (refreshEl){

                e.preventDefault();

                const menu = app?.service?.('menu');
                if (!menu) return;

                const role = refreshEl.dataset.role;
                menu.refresh(role);

                return;
            }

            /* ==================================================
               CONFIRM ACTION
               data-confirm="Message"
            ================================================== */

            const confirmEl = e.target.closest('[data-confirm]');
            if (confirmEl){

                const message = confirmEl.dataset.confirm || 'Are you sure?';

                if (!window.confirm(message)){
                    e.preventDefault();
                    return false;
                }
            }

        });
    }

    function init(){
        bind();
        console.log('[ui.actions] ready');
    }

    return { init };
});