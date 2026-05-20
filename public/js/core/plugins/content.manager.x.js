__BORA_REGISTER_PLUGIN__('content.manager', async function(scope){

    const hooks = await scope.getService('hooks');
    const meta  = await scope.getService('meta');
    const cache = await scope.getService('pageCache');

    /*
    |------------------------------------------------------------------
    | Utilities
    |------------------------------------------------------------------
    */

    function withAjaxParam(url){

        const parsed = new URL(
            url,
            window.__APP_BASE_PATH__ || window.location.origin
        );

        parsed.searchParams.set('t', '1');

        return parsed.toString();
    }

    function executeScripts(container){

        const scripts = container.querySelectorAll('script');

        scripts.forEach(oldScript => {

            const newScript = document.createElement('script');

            [...oldScript.attributes].forEach(attr => {
                newScript.setAttribute(attr.name, attr.value);
            });

            newScript.textContent = oldScript.textContent;

            oldScript.parentNode.replaceChild(
                newScript,
                oldScript
            );
        });
    }

    function injectScripts(scripts = []){

        scripts.forEach(src => {

            if (
                document.querySelector(
                    `script[src="${src}"]`
                )
            ){
                return;
            }

            const script = document.createElement('script');

            script.src = src;
            script.async = true;

            document.body.appendChild(script);
        });
    }

    /*
    |------------------------------------------------------------------
    | Rendering
    |------------------------------------------------------------------
    */

    async function render(response){

        if (!response) return;

        scope.emit('content:beforeRender', {
            response
        });

        /*
        |--------------------------------------------------------------
        | Block rendering
        |--------------------------------------------------------------
        */

        if (response.blocks){

            /*
            |----------------------------------------------------------
            | Submenus
            |----------------------------------------------------------
            */

            if (response.blocks.submenus !== undefined){

                const el = document.querySelector(
                    '.submenu-area .sub_menu'
                );

                if (el){
                    el.innerHTML = response.blocks.submenus;
                }
            }

            /*
            |----------------------------------------------------------
            | Sidebar
            |----------------------------------------------------------
            */

            if (response.blocks.sidebar_menu !== undefined){

                const el = document.querySelector(
                    '.features-list'
                );

                if (el){
                    el.innerHTML =
                        response.blocks.sidebar_menu;
                }
            }

            /*
            |----------------------------------------------------------
            | Main content
            |----------------------------------------------------------
            */

            if (response.blocks.content !== undefined){

                const el = document.querySelector(
                    '.content-area'
                );

                if (el){

                    el.innerHTML =
                        response.blocks.content;

                    executeScripts(el);

                    const actions =
                        await scope.getPlugin(
                            'app.actions'
                        );

                    actions?.scan?.('.content-area');
                }
            }

            /*
            |----------------------------------------------------------
            | External scripts
            |----------------------------------------------------------
            */

            if (response.blocks.scripts){

                injectScripts(
                    response.blocks.scripts
                );
            }
        }

        /*
        |--------------------------------------------------------------
        | Raw HTML fallback
        |--------------------------------------------------------------
        */

        else if (response.html){

            const el = document.querySelector(
                '.content-area'
            );

            if (el){

                el.innerHTML = response.html;

                executeScripts(el);
            }
        }

        /*
        |--------------------------------------------------------------
        | Meta
        |--------------------------------------------------------------
        */

        if (response.meta){

            meta?.apply?.(response.meta);
        }

        /*
        |--------------------------------------------------------------
        | Mounted lifecycle
        |--------------------------------------------------------------
        */

        const root =
            document.querySelector('#page_content');

        scope.emit('view:mounted', {
            root,
            type: 'page',
            url: response?.url,
            response
        });

        scope.emit('content:afterRender', {
            response
        });
    }

    /*
    |------------------------------------------------------------------
    | Cache Revalidation
    |------------------------------------------------------------------
    */

    async function revalidate(url, cachedEntry){

        try {

            const response = await fetch(

                withAjaxParam(url),

                {
                    headers: {
                        'X-Requested-With':
                            'XMLHttpRequest'
                    }
                }
            );

            const fresh = await response.json();

            if (!fresh.ok) return;

            if (
                cache.hasChanged(
                    cachedEntry,
                    fresh
                )
            ){

                cache.set(url, fresh);

                await render(fresh);

                hooks?.call?.(
                    'page.cacheUpdated',
                    url,
                    fresh
                );

                scope.emit(
                    'page:cacheUpdated',
                    {
                        url,
                        response:fresh
                    }
                );
            }

        } catch(err){

            console.warn(
                '[content.manager] revalidate failed',
                err
            );
        }
    }

    /*
    |------------------------------------------------------------------
    | Response Handler
    |------------------------------------------------------------------
    */

    async function handleResponse({
        url,
        response
    }){

        if (!url || !response){
            return;
        }

        /*
        |--------------------------------------------------------------
        | Cache response
        |--------------------------------------------------------------
        */

        if (response.ok){

            cache.set(url, response);
        }

        /*
        |--------------------------------------------------------------
        | Render
        |--------------------------------------------------------------
        */

        await render(response);

        /*
        |--------------------------------------------------------------
        | Revalidate stale cache in background
        |--------------------------------------------------------------
        */

        const cached = cache.get(url);

        if (cached){

            revalidate(url, cached);
        }

        /*
        |--------------------------------------------------------------
        | Final lifecycle
        |--------------------------------------------------------------
        */

        scope.emit('page:rendered', {
            url,
            response
        });
    }

    /*
    |------------------------------------------------------------------
    | Public API
    |------------------------------------------------------------------
    */

    return {

        async render(response){

            return render(response);
        },

        mount(){

            console.log(
                '[content.manager] mounted'
            );

            /*
            |----------------------------------------------------------
            | Main response pipeline
            |----------------------------------------------------------
            */

            scope.on(
                'page:response',
                handleResponse
            );
        }
    };
});