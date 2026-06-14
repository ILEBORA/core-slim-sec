__BORA_REGISTER_SERVICE__(
    'navigation',
    async function(scope){

        const state   = await scope.getService('state');
        const router  = await scope.getService('router');
        const hooks   = await scope.getService('hooks');
        const meta    = await scope.getService('meta');
        const uiStack = await scope.getService('uiStack');        

        const app     = window.__BORA_APP__;
        let overlayTimer = null;
        let overlayVisible = false;
        const overlay = () => app?.plugin?.('overlay');
        const alerts  = () => app?.plugin?.('alerts');

        let currentRoute = normalizeUrl(window.location);
        let currentXHR   = null;

        /* --------------------------------------------------
         * Helpers
         * -------------------------------------------------- */

        function normalizeO(url){
            return url.split('?')[0].replace(/\/+$/, '');
        }

        function normalize(url){

            return url;
            return url
                .split('?')[0]
                .replace(/\/+$/, '');
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

        async function renderPage(response){

            if (!response) return;

            if (response.blocks){

                if (response.blocks.submenus !== undefined){
                    // alert('submenu block');
                    const el = document.querySelector('.submenu-area .sub_menu');
                    if (el) el.innerHTML = response.blocks.submenus;
                }

                if (response.blocks.content !== undefined){
                    const el = document.querySelector('.content-area');
                    if (el){
                        el.innerHTML = response.blocks.content;
                        executeScripts(el);

                        const actions =
                            await scope.getPlugin(
                                'app.actions'
                            );

                        actions?.scan('.content-area');
                        
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
            console.trace('fetchJson called:', url);
            if (currentXHR){
                currentXHR.abort();
            }
            // alert('here x');
            return new Promise((resolve, reject)=>{
                
                const xhr = new XMLHttpRequest();
                currentXHR = xhr;
                // alert(url);
                // xhr.open('GET', url + '?t=1', true);
                
                /*
                |--------------------------------------------------------------------------
                | Proper query handling
                |--------------------------------------------------------------------------
                */

                const base = window.__APP_BASE_PATH__ || '';

                const parsed = new URL(url, base);

                parsed.searchParams.set(
                    't',
                    '1'
                );

                xhr.open(
                    'GET',
                    parsed.toString(),
                    true
                );

                //

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

            const cleanUrl = url;//normalize(url);

            alert(cleanUrl);

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
            // ov?.show?.('Loading...', { progress: 5 });
            // delay showing overlay
            overlayTimer = setTimeout(() => {
                ov?.show?.('Loading...', { progress: 5 });
                overlayVisible = true;
            }, 120);

            await new Promise(requestAnimationFrame);

            try {
                alert('go');
                const json = await fetchJson(cleanUrl);

                scope.emit('page.response', {
                    url: cleanUrl,
                    response: json,
                    options
                });

                // return;

                const isValid = json?.ok === true || json?.success === true;
                if (!isValid){
            
                    alertBora.notifyRich({
                        type: 'error',
                        title: 'Permission Errord',
                        body: json.message,
                        delay: 4,
                        sound: true,
                        onClick: () => {
                            this.navigation.go(``);
                        }
                    });

                    uiStack.closeTop();

                    scope.emit('page.loadError', cleanUrl, json);

                    if (overlayVisible) ov?.hide?.(true);

                    return Promise.reject(json);
                    // throw new Error('Invalid response');
                }else{

                    // ov?.setProgress?.(90);
                    clearTimeout(overlayTimer);

                    if (overlayVisible){
                        ov?.setProgress?.(90);
                    }

                    //TODO
                    if (!(scope?.config?.dev ?? false)) { 
                        // clearConsole();
                    }

                    // renderPage(json);

                    //crumbs
                    scope.emit('breadcrumbs:resolve', {
                        url:cleanUrl, 
                        response:json
                    });

                    currentRoute = cleanUrl;

                    if (!options.replace){
                        history.pushState({ url: cleanUrl }, '', cleanUrl);
                    } else {
                        history.replaceState({ url: cleanUrl }, '', cleanUrl);
                    }

                    state?.set?.('route', cleanUrl);

                    scope.emit('route:changed', {url:cleanUrl});

                    if (overlayVisible){
                        ov?.setProgress?.(100);
                    }

                    scope.emit('page.afterLoad', {url:cleanUrl, response:json});
                    scope.emit('page.loaded', {url:cleanUrl});

                    // ov?.hide?.(true);
                    if (overlayVisible){
                        ov?.hide?.(true);
                    }

                    return json;
                }

            } catch (err){

                if (err.name === 'AbortError'){
                    return;
                }

                scope.emit('page.loadError', cleanUrl, err);
                // ov?.hide?.(true);
                if (overlayVisible){
                    ov?.hide?.(true);
                }

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
                cleanRoute = normalizeUrl(cleanRoute || window.location);
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

        async function restoreFromUrl(scope){

            const navigator = await scope.getService('navigator');

            const url = new URL(window.location);

            const route   = url.searchParams.get('route');
            const surface = url.searchParams.get('surface');

            if (!route) return;

            const params = Object.fromEntries(url.searchParams.entries());

            navigator.go({
                route,
                params,
                surface: surface || 'page'
            });
        }

        window.addEventListener('popstate', async (e) => {
            const uiStack  = await scope.getService('uiStack');
            const navigator = await scope.getService('navigator');
            const popup    = await scope.getPlugin('popup');

            const url = new URL(window.location);
            const route   = url.searchParams.get('route');
            const surface = url.searchParams.get('surface');

            // 🔥 1. UI precedence (your requirement — correct)
            if (uiStack && uiStack.size() > 0){

                uiStack.closeTop();

                // ⚠️ BUT: also reflect that in URL
                if (!route || surface !== 'popup'){
                    // URL already says no popup → fine
                    return;
                }

                // URL still says popup → fix it
                const cleanUrl = new URL(window.location);
                cleanUrl.searchParams.delete('route');
                cleanUrl.searchParams.delete('surface');
                cleanUrl.searchParams.delete('id');
                cleanUrl.searchParams.delete('tab');

                history.replaceState({}, '', cleanUrl);

                return;
            }

            // 🔥 2. No UI stack → follow URL
            if (!route){
                popup?.closeActive?.();
                
                const cleanUrl = normalizeUrl(window.location);
                await go(cleanUrl, { replace:true });
                return;
            }

            const params = Object.fromEntries(url.searchParams.entries());

            await navigator.go({
                route,
                params,
                surface: surface || 'page'
            });
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