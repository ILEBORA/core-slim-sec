__BORA_REGISTER_SERVICE__('popup', function(scope){

    const app = window.__BORA_APP__;

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

    function closeActive(){
        const popupPlugin = app?.plugin?.('BoraPopupV2');
        popupPlugin?.activePopup?.close();
    }

    function open(options){

        const popupPlugin = app?.plugin?.('BoraPopupV2');

        if (!popupPlugin){
            console.warn('[popup] BoraPopupV2 not available');
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
            callback = null
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

        const popup = popupPlugin.create({
            onOpen,
            onClose
        });

        // Apply size class
        const container = document.getElementById('diagPop');
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