__BORA_REGISTER_PLUGIN__('popup', async function(scope){

    const uiStack = await scope.getService('uiStack');
    const popupCore = await scope.getPlugin('popup.core');

    function buildFormUrl({ module, group, tab='add', id=null, meta=null }){

        const parts = ['api/modules', module, 'form', group, tab];

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
            onClose,
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

        if (finalUrl){
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

    return {
        open,
        closeActive,
        buildFormUrl,
        buildViewUrl
    };
});