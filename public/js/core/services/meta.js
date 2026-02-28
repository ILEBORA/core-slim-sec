__BORA_REGISTER_SERVICE__('meta', function(scope){

    function setTitle(title){
        if(title) document.title = title;
    }

    function setDescription(desc){
        if(!desc) return;

        let tag = document.querySelector('meta[name="description"]');
        if(!tag){
            tag = document.createElement('meta');
            tag.setAttribute('name','description');
            document.head.appendChild(tag);
        }
        tag.setAttribute('content', desc);
    }

    function setCanonical(url){
        if(!url) return;

        let tag = document.querySelector('link[rel="canonical"]');
        if(!tag){
            tag = document.createElement('link');
            tag.setAttribute('rel','canonical');
            document.head.appendChild(tag);
        }

        const full = url.startsWith('http')
            ? url
            : new URL(url, window.location.origin).href;

        tag.setAttribute('href', full);
    }

    function apply(meta){
        if(!meta) return;

        setTitle(meta.page_title);
        setDescription(meta.description);
        setCanonical(meta.url);

        scope.emit('page.metaUpdated', meta);
    }

    return { apply };
});