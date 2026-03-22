__BORA_REGISTER_SERVICE__(
    'navigation',
    async function(scope){

        const state   = await scope.getService('state');
        const router  = await scope.getService('router');
        const hooks   = await scope.getService('hooks');
        const meta    = await scope.getService('meta');

        const app     = window.__BORA_APP__;
        const overlay = () => app?.plugin?.('Overlay');

        let currentRoute = normalizeUrl(window.location);
        let currentXHR   = null;

        /* --------------------------------------------------
         * Helpers
         * -------------------------------------------------- */

        function normalize(url){
            return url.split('?')[0].replace(/\/+$/, '');
        }

        function normalizeUrl(fullUrl){
            const base = window.__APP_BASE_PATH__ || '';

            if (!fullUrl) return '/';

            fullUrl = String(fullUrl);

            if (base && fullUrl.startsWith(base)){
                fullUrl = fullUrl.slice(base.length);
            }

            // remove query
            fullUrl = fullUrl.split('?')[0];

            // if (!fullUrl.startsWith('/')){
            //     fullUrl = '/' + fullUrl;
            // }

            return fullUrl || '';
        }

        function executeScripts(container){

            const scripts = container.querySelectorAll('script');

            scripts.forEach(oldScript => {

                const type = (oldScript.type || '').trim();

                // 🚫 Skip non-JS scripts (like text/template, application/json, etc.)
                if (type && type !== 'text/javascript' && type !== 'module') {
                    return;
                }

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

        function executeScriptsO(container){
            const scripts = container.querySelectorAll('script');

            scripts.forEach(oldScript => {
                const newScript = document.createElement('script');
                if (oldScript.src) {
                    newScript.src = oldScript.src;
                } else {
                    newScript.textContent = oldScript.textContent;
                }
                console.log('newScript:: ',newScript);
                document.body.appendChild(newScript);
                oldScript.remove();
            });
        }

        function injectScripts(htmlString){

            const wrapper = document.createElement('div');
            wrapper.innerHTML = htmlString;

            wrapper.querySelectorAll('script').forEach(script => {

                const type = (script.type || '').trim();

                if (type && type !== 'text/javascript' && type !== 'module') {
                    return;
                }

                const newScript = document.createElement('script');

                if (script.src) {
                    newScript.src = script.src;
                } else {
                    newScript.textContent = script.textContent;
                }

                document.body.appendChild(newScript);
            });
        }

        function injectScriptsO(htmlString){
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

        /* --------------------------------------------------
         * XHR WITH PROGRESS
         * -------------------------------------------------- */

        function fetchJson(url){

            if (currentXHR){
                currentXHR.abort();
            }

            return new Promise((resolve, reject)=>{

                const xhr = new XMLHttpRequest();
                currentXHR = xhr;

                xhr.open('GET', url + '?t=1', true);
                xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');

                xhr.onprogress = function(e){

                    if (!e.lengthComputable) return;

                    const percent = Math.round((e.loaded / e.total) * 100);

                    const ov = overlay();
                    if (ov && ov.setProgress){
                        ov.setProgress(percent);
                    }
                };

                xhr.onload = function(){

                    if (xhr.status >= 200 && xhr.status < 300){

                        try {
                            const json = JSON.parse(xhr.responseText);
                            resolve(json);
                        } catch(err){
                            reject(err);
                        }

                    } else {
                        reject(new Error('HTTP ' + xhr.status));
                    }
                };

                xhr.onerror = function(){
                    reject(new Error('Network error'));
                };

                xhr.onabort = function(){
                    reject({ name:'AbortError' });
                };

                xhr.send();
            });
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

            scope.emit('page.beforeLoad', cleanUrl);

            const ov = overlay();
            ov?.show?.('Loading...', { progress: 5 });

            try {

                const json = await fetchJson(cleanUrl);

                if (!json.ok){
                    throw new Error('Invalid response');
                }

                ov?.setProgress?.(90);

                //TODO
                if(!scope?.config.dev??false){ 
                    // clearConsole();
                }

                renderPage(json);

                currentRoute = cleanUrl;

                if (!options.replace){
                    history.pushState({ url: cleanUrl }, '', cleanUrl);
                } else {
                    history.replaceState({ url: cleanUrl }, '', cleanUrl);
                }

                state?.set?.('route', cleanUrl);

                scope.emit('route:changed', cleanUrl);

                ov?.setProgress?.(100);

                scope.emit('page.afterLoad', cleanUrl, json);
                scope.emit('page.loaded', cleanUrl);

                

                ov?.hide?.(true);

                return json;

            } catch (err){

                if (err.name === 'AbortError'){
                    return;
                }

                scope.emit('page.loadError', cleanUrl, err);
                ov?.hide?.(true);

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

        function normalizeUrl(fullUrl){
            const base = window.__APP_BASE_PATH__ || '';

            if (!fullUrl) return '/';

            fullUrl = String(fullUrl);

            if (base && fullUrl.startsWith(base)){
                fullUrl = fullUrl.slice(base.length);
            }

            // remove query
            fullUrl = fullUrl.split('?')[0];

            // if (!fullUrl.startsWith('/')){
            //     fullUrl = '/' + fullUrl;
            // }

            return fullUrl || '';
        }

        function highlight(cleanRoute){
            $(function(){
                cleanRoute = normalizeUrl(cleanRoute || window.location.location);
                const items = [...document.querySelectorAll('.features-item')];

                let bestItem = null;
                let bestLength = -1;

                items.forEach(item => {

                    const dataUrl = (item.dataset.url || '').replace(/^\/|\/$/g,'');

                    if (!dataUrl) return;

                    if (
                        cleanRoute === dataUrl ||
                        cleanRoute.startsWith(dataUrl + '/')
                    ) {
                        if (dataUrl.length > bestLength) {
                            bestLength = dataUrl.length;
                            bestItem = item;
                        }
                    }
                });

                items.forEach(i => i.classList.remove('active'));
                bestItem?.classList.add('active');
            });
        }

        window.addEventListener('popstate', async (e)=>{
            const uiStack = await scope.getService('uiStack');
            if(uiStack && uiStack.size() > 0){
                uiStack.closeTop();
                // restore history so navigation does not occur
                history.pushState(e.state, '', window.location);
                return;
            }

            const url = e.state?.url || normalizeUrl(window.location);
            await go(url, { replace:true });
        });

        return {
            go,
            navigate,
            reload,
            back,
            highlight
        };
    },
    {
        requires: ['state','router','hooks','meta']
    }
);
