__BORA_REGISTER_PLUGIN__('ContentManager', async function(scope){

    const $     = await scope.getService('jquery');
    const state = await scope.getService('state');
    const hooks = await scope.getService('hooks');
    const meta  = await scope.getService('meta');
    const cache = await scope.getService('pageCache');

    let currentRequest = null;

    // ----------------------------------------
    // 🔑 Cache Key (URL + relevant state)
    // ----------------------------------------
    function getCacheKey(url){
        return url + '::' + JSON.stringify({
            filter: state.get('filter'),
            page: state.get('pageNumber')
        });
    }

    // ----------------------------------------
    // 🛑 Abort previous request
    // ----------------------------------------
    function abortPrevious(){
        if(currentRequest && currentRequest.readyState !== 4){
            currentRequest.abort();
        }
    }

    // ----------------------------------------
    // 🧠 Hydrate state (single source of truth)
    // ----------------------------------------
    function hydrate(response){
        state.set('page', {
            url: response?.url,
            blocks: response?.blocks || {},
            meta: response?.meta || {}
        });
    }

    // ----------------------------------------
    // 🎯 Pure renderer (state → DOM)
    // ----------------------------------------
    function renderPage(){

        const page = state.get('page');
        if(!page) return;

        const blocks = page.blocks || {};

        if(blocks.content){
            $('.content-area').html(blocks.content);
        }

        if(blocks.sidebar_menu){
            $('.features-list').html(blocks.sidebar_menu);
        }

        if(blocks.submenus){
            $('.submenu-area .sub_menu')?.html(blocks.submenus);
        }

        meta?.apply(page.meta);

        const $root = $('#page_content');

        scope.emit('view:mounted', {
            root: $root,
            type: 'page',
            url: page.url
        });
    }

    // ----------------------------------------
    // 📦 Handle response (cache + hydrate)
    // ----------------------------------------
    function handleResponse(url, response, fromCache = false){

        const key = getCacheKey(url);

        if(response?.ok){
            cache.set(key, {
                data: response,
                ts: Date.now()
            });
        }

        hydrate(response);

        scope.emit('page.afterLoad', {
            url,
            response,
            force: !fromCache
        });
    }

    // ----------------------------------------
    // 🔄 Background revalidation
    // ----------------------------------------
    function revalidate(url, cachedEntry){

        $.ajax({
            url: url + '?t=1',
            method: 'GET',
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            dataType: 'json'
        }).done((fresh)=>{

            if(!fresh?.ok) return;

            if(cache.hasChanged(cachedEntry, fresh)){

                const key = getCacheKey(url);

                cache.set(key, {
                    data: fresh,
                    ts: Date.now()
                });

                hydrate(fresh);

                hooks?.call('page.cacheUpdated', url, fresh);
            }
        });
    }

    // ----------------------------------------
    // 🚀 Fetch logic
    // ----------------------------------------
    function fetchAndRender(url, options = {}){

        if(!url) return;

        const force = options.force === true;

        hooks?.call('page.beforeLoad', url);

        abortPrevious();

        const key = getCacheKey(url);
        const cached = cache.get(key);

        // ✅ Serve from cache
        if(!force && cached && !cache.isStale(cached)){
            handleResponse(url, cached.data, true);
            revalidate(url, cached);
            return;
        }

        // UI feedback
        $('.main-content').fadeTo(150, 0.3);

        currentRequest = $.ajax({
            url: url + '?t=1',
            method: 'GET',
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            dataType: 'json',

            success(response){
                handleResponse(url, response, false);
                $('.main-content').fadeTo(200, 1);
            },

            error(xhr, status){
                if(status === 'abort') return;
                hooks?.call('page.loadError', url, xhr);
                $('.main-content').fadeTo(200, 1);
            },

            complete(){
                hooks?.call('page.loadComplete', url);
            }
        });
    }

    // ----------------------------------------
    // 🔁 Route → Fetch
    // ----------------------------------------
    function onRouteChange(url){
        if(!url) return;
        fetchAndRender(url);
    }

    // ----------------------------------------
    // 🔄 State → Fetch (for hybrid cases)
    // ----------------------------------------
    function bindStateTriggers(){

        // Example: filter affects server response
        state.subscribe('filter', () => {
            const url = state.get('route');
            if(url){
                fetchAndRender(url, { force: true });
            }
        });

        // Example: pagination
        state.subscribe('pageNumber', () => {
            const url = state.get('route');
            if(url){
                fetchAndRender(url, { force: true });
            }
        });
    }

    // ----------------------------------------
    // 🧩 Mount
    // ----------------------------------------
    function mount(){

        console.log('[ContentManager] mounted');

        // Route drives everything
        state.subscribe('route', onRouteChange);

        // Page rendering driven by state
        state.subscribe('page', renderPage, true);

        // Bind state-driven fetch triggers
        bindStateTriggers();
    }

    return {
        mount,
        fetch: fetchAndRender,
        hydrate
    };
});