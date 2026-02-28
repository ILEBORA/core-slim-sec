__BORA_REGISTER_PLUGIN__('ContentManager', function(scope){

    const state = scope.getService('state');
    const hooks = scope.getService('hooks');
    const meta  = scope.getService('meta');
    const cache = scope.getService('pageCache');

    let currentRequest = null;

    function abortPrevious(){
        if(currentRequest && currentRequest.readyState !== 4){
            currentRequest.abort();
        }
    }

    function render(response){

        if(response.blocks){
            if(response.blocks.content){
                $('.content-area').html(response.blocks.content);
            }
            if(response.blocks.sidebar_menu){
                $('.features-list').html(response.blocks.sidebar_menu);
            }
            if(response.blocks.submenus){
                $('.submenu-area .sub_menu').html(response.blocks.submenus);
            }
        }

        meta?.apply(response.meta);
    }

    function revalidate(url, cachedEntry){

        $.ajax({
            url: url + '?t=1',
            method: 'GET',
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            dataType: 'json'
        }).done((fresh)=>{

            if(!fresh.ok) return;

            if(cache.hasChanged(cachedEntry, fresh)){
                cache.set(url, fresh);
                render(fresh);
                hooks?.call('page.cacheUpdated', url, fresh);
            }
        });
    }

    function fetchAndRender(url){

        hooks?.call('page.beforeLoad', url);

        abortPrevious();

        const cached = cache.get(url);

        if(cached && !cache.isStale(cached)){
            render(cached.data);
            revalidate(url, cached);
            hooks?.call('page.afterLoad', url, cached.data, true);
            return;
        }

        $('.main-content').fadeTo(150, 0.3);

        currentRequest = $.ajax({
            url: url + '?t=1',
            method: 'GET',
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            dataType: 'json',

            success(response){

                if(response.ok){
                    cache.set(url, response);
                }

                render(response);

                hooks?.call('page.afterLoad', url, response, false);
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

    function onRouteChange(url){
        if(!url) return;
        fetchAndRender(url);
    }

    return {
        mount(){
            state.subscribe('route', onRouteChange);
        }
    };
});