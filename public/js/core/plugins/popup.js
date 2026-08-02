__BORA_REGISTER_PLUGIN__('popup', async function(scope){

    const uiStack = await scope.getService('ui.stack');
    const popupCore = await scope.getPlugin('popup.core');

    function buildFormUrl({ module, group, tab='add', id=null, meta=null }){

        // FIXED ORDER
        const parts = ['api/modules', module, group, 'form', tab];

        if (id) parts.push(id);

        let url = parts.join('/');

        if (meta && typeof meta === 'object'){
            const qs = new URLSearchParams(meta).toString();
            if (qs) url += '?' + qs;
        }

        return url;
    }

    function buildViewUrl({ module, view, tab='view', id=null }){

        const parts = ['api/modules', module, 'view', view, tab];

        if (id) parts.push(id);

        return parts.join('/');
    }

    async function closeActive(){
        // const popupCore = await app?.plugin?.('popup');
        // popupCore?.activePopup?.close();
        popupCore.setActive(null);
        
        await uiStack?.closeTop();
    }

    async function open(options){

        if (!popupCore){
            console.warn('[popup] not available');
            return;
        }

        const {
            mode = 'form',        // form | view | raw
            module,
            group,
            view,
            tab = 'add',
            id = null,
            meta = null,
            url = null,
            html = null,
            size = 'md',
            onOpen = null,
            onLoaded = null,
            onClose = null,
            callback = null,
            tabs = null,
            activeTab = null,
        } = options;

        let finalUrl = url;

        if (!finalUrl){

            if (mode === 'form'){
                finalUrl = buildFormUrl({ module, group, tab, id, meta });
            }

            if (mode === 'view'){
                finalUrl = buildViewUrl({ module, view, tab, id });
            }
        }

        const popup = popupCore.create({
            onOpen,
            onClose: () => {

                // 1. run user-defined onClose if exists
                if (typeof options.onClose === 'function'){
                    options.onClose();
                }

                // 2. 🔥 central URL cleanup
                const url = new URL(window.location);

                if (url.searchParams.get('surface') === 'popup'){
                    url.searchParams.delete('route');
                    url.searchParams.delete('surface');
                    url.searchParams.delete('id');
                    url.searchParams.delete('tab');

                    history.replaceState({}, '', url);
                }
            },
            onLoaded,
            tabs,
            activeTab
        });

        popupCore.setActive(popup); 

        // Apply size class
        // const container = document.getElementById('bora_popup');
        const container = popup?.$popup?.[0];
        if (container){
            container.classList.remove('diag-sm','diag-md','diag-lg','diag-full');
            container.classList.add('diag-' + size);
        }

        if (tabs && tabs.length){
            // Skip initial view load
            popup.open('<div id="tabContentArea"></div>', callback);
        }
        else if (finalUrl){
            popup.open(finalUrl, callback);
        }
        else if (html){
            popup.open(html, callback);
        }
        else{
            console.warn('[popup] insufficient parameters');
        }

        return popup;
    }

    async function openPopupSmart({ key, id, tab, factory }) {

        const active = popupCore.getActive();

        // Helper: ensure popup is still alive
        const isAlive = (p) => p && p.$popup && p.$popup.length;

        if (
            isAlive(active) &&
            active._key === key &&
            active._id === id
        ){
            active.goToTab(tab);
            return active;
        }

        const config = factory(id);
        config.activeTab = tab;

        const instance = await open(config);

        // Attach identity
        instance._key = key;
        instance._id = id;

        return instance;
    }
    
    return {
        open,
        closeActive,
        buildFormUrl,
        buildViewUrl,
        openPopupSmart
    };
});