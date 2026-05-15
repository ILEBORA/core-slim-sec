__BORA_REGISTER_SERVICE__('face', await function(scope){

    function resolveFace(path){

        path = normalizeUrl(path);

        if(path === 'portal' || path.startsWith('portal/')){
            return 'client';
        }

        if(path === 'bo' || path.startsWith('bo/')){
            return 'admin';
        }

        return 'guest';
    }

    function current(){
        return resolve(normalizeUrl(window.location.pathname));
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

    return {
        resolve,
        current
    };

});