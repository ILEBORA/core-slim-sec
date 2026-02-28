__BORA_REGISTER_SERVICE__('pageCache', function(scope){

    const prefix = 'page:';
    const defaultTTL = 60_000; // 60 seconds

    function get(url){
        const raw = localStorage.getItem(prefix + url);
        if(!raw) return null;

        try {
            return JSON.parse(raw);
        } catch(e){
            localStorage.removeItem(prefix + url);
            return null;
        }
    }

    function set(url, payload){
        localStorage.setItem(prefix + url, JSON.stringify({
            version: payload.version ?? 0,
            meta: payload.meta ?? {},
            data: payload,
            cachedAt: Date.now()
        }));
    }

    function remove(url){
        localStorage.removeItem(prefix + url);
    }

    function isStale(entry, ttl = defaultTTL){
        return (Date.now() - entry.cachedAt) > ttl;
    }

    function hasChanged(oldEntry, fresh){
        const oldVersion = oldEntry?.data?.version ?? 0;
        const newVersion = fresh?.version ?? 0;
        return oldVersion !== newVersion;
    }

    return {
        get,
        set,
        remove,
        isStale,
        hasChanged
    };
});