__BORA_REGISTER_SERVICE__(
    'navigation',
    async function(scope){

        const state  = await scope.getService('state');
        const router = await scope.getService('router');
        const hooks  = await scope.getService('hooks');
        const meta   = await scope.getService('meta');

        let currentRoute = window.location.pathname;
        let currentAbort = null;

        /* --------------------------------------------------
         * Helpers
         * -------------------------------------------------- */

        function normalize(url){
            return url.split('?')[0].replace(/\/+$/, '');
        }

        function executeScripts(container){

            const scripts = container.querySelectorAll('script');

            scripts.forEach(oldScript => {

                const newScript = document.createElement('script');

                if (oldScript.src) {
                    newScript.src = oldScript.src;
                } else {
                    newScript.textContent = oldScript.textContent;
                }

                document.body.appendChild(newScript);
                oldScript.remove();
            });
        }

        function injectScripts(htmlString){

            const wrapper = document.createElement('div');
            wrapper.innerHTML = htmlString;

            wrapper.querySelectorAll('script').forEach(script => {

                const newScript = document.createElement('script');

                if (script.src) {
                    newScript.src = script.src;
                } else {
                    newScript.textContent = script.textContent;
                }

                document.body.appendChild(newScript);
            });
        }

        function renderPage(response){

            if (!response) return;

            if (response.blocks){

                if (response.blocks.submenus !== undefined){
                    const el = document.querySelector('.submenu-area .sub_menu');
                    if (el) el.innerHTML = response.blocks.submenus;
                }

                if (response.blocks.sidebar_menu !== undefined){
                    const el = document.querySelector('.features-list');
                    // if (el) el.innerHTML = response.blocks.sidebar_menu;
                }

                if (response.blocks.content !== undefined){
                    const el = document.querySelector('.content-area');
                    if (el){
                        el.innerHTML = response.blocks.content;
                        executeScripts(el);
                    }
                }

                if (response.blocks.scripts){
                    injectScripts(response.blocks.scripts);
                }

            } else if (response.html){

                const el = document.querySelector('.content-area');
                if (el){
                    el.innerHTML = response.html;
                    executeScripts(el);
                }
            }

            if (response.meta){
                meta?.apply(response.meta);
            }
        }

        async function fetchJson(url){

            if (currentAbort){
                currentAbort.abort();
            }

            currentAbort = new AbortController();

            const response = await fetch(url + '?t=1', {
                headers: {
                    'X-Requested-With':'XMLHttpRequest'
                },
                signal: currentAbort.signal
            });

            if (!response.ok){
                throw new Error('HTTP ' + response.status);
            }

            return response.json();
        }

        /* --------------------------------------------------
         * Core Navigation
         * -------------------------------------------------- */

        async function go(url, options = {}){

            if (!url) return Promise.resolve();

            const cleanUrl = normalize(url);

            const guardResult = await router?.runGuards?.(cleanUrl, currentRoute);

            if (guardResult && guardResult.allow === false){

                if (guardResult.redirect){
                    return go(guardResult.redirect);
                }

                console.warn('[Navigation blocked]');
                return Promise.reject('blocked');
            }

            hooks?.call?.('page.beforeLoad', cleanUrl);

            try {

                const json = await fetchJson(cleanUrl);

                if (!json.ok){
                    throw new Error('Invalid response');
                }

                renderPage(json);

                currentRoute = cleanUrl;

                if (!options.replace){
                    history.pushState({ url: cleanUrl }, '', cleanUrl);
                } else {
                    history.replaceState({ url: cleanUrl }, '', cleanUrl);
                }

                state?.set?.('route', cleanUrl);

                scope.emit('page.afterLoad', {
                    url:cleanUrl, 
                    response:json
                });
                scope.emit('page.loaded', {url:cleanUrl});

                return json;

            } catch (err){

                if (err.name === 'AbortError'){
                    return;
                }

                hooks?.call?.('page.loadError', cleanUrl, err);
                console.error('[Navigation error]', err);
                throw err;
            }
        }

        function reload(){
            return go(currentRoute, { replace:true });
        }

        function back(){
            history.back();
        }

        function navigate(url){
            return go(url);
        }

        /* --------------------------------------------------
         * History Listener
         * -------------------------------------------------- */

        window.addEventListener('popstate', async (e)=>{
            const url = e.state?.url || window.location.pathname;
            await go(url, { replace:true });
        });

        /* --------------------------------------------------
         * Public API
         * -------------------------------------------------- */

        return {
            go,
            navigate,
            reload,
            back
        };
    },
    {
        requires: ['state','router','hooks','meta']
    }
);