
function _loadCacheScript(l,obj,v,a){
    logTest('Here _loadCacheScript '+ obj);

    var b = document.createElement("script");

    if(b != null || typeof b != 'undefined'){

        b.onload=function(){

            _cacheScript(obj,v,l);

            // 🔴 Tell runtime new plugins may exist
            if(window.__BORA_APP__?.isStarted()){
                __BORA_APP__.integratePending();
            }

            a && a();
        };

        b.setAttribute("src",l);
        document.getElementsByTagName("head")[0].appendChild(b);

        if (b.parentNode) {
            b.parentNode.removeChild(b);
        }
    }

    b = null;
}
function _loadCacheScriptO(l,obj,v,a){
    logTest('Here _loadCacheScript '+ obj);
    var b=document.createElement("script");
    if(b != null || typeof b != 'undefined'){ //TODO:: fix cache
        
        b.onload=function(){
            _cacheScript(obj,v,l);
            a&&a();
        };

        b.setAttribute("src",l);
        document.getElementsByTagName("head")[0].appendChild(b);
        // b.remove();
        // Instead of b.remove(), use the following:
        if (b.parentNode) {
            b.parentNode.removeChild(b);
        }
    }
    b = null;
};
function _injectScript(c,euri,e,a){
    logTest('Here _injectScript '+ euri);
    var b = document.createElement("script");
    b.type="text/javascript";
    b.classList.add("scj");
    c = JSON.parse(c);
    var f = document.createTextNode(c.content);
    b.appendChild(f);
    document.getElementsByTagName("head")[0].appendChild(b); //TODO::fix cannot read property
    // b.remove();
    // Instead of b.remove(), use the following:
    if (b.parentNode) {
        b.parentNode.removeChild(b);
    }
    b=null;
    c.version != e && localStorage.removeItem(euri); 
    a&&a();
};

function requireScript(obj){
    logTest('Here '+ obj.id);
    if(engineSettings.cachescripts){
        var itm = localStorage.getItem(obj.id);
        (null == itm) ? _loadCacheScript(obj.uri,obj.id,obj.version,obj.callback) : _injectScript(itm,obj.id,obj.version,obj.callback);
        // _loadCacheScript(obj.uri,obj.id,obj.version,obj.callback); //force load
    }else{
        _loadCacheScript(obj.uri,obj.id,obj.version,obj.callback);
    }
};