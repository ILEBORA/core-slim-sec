__BORA_REGISTER_SERVICE__('face', function(scope){

    function resolve(path){

        if(path.startsWith('/portal/')) return 'client';
        if(path.startsWith('/bo/'))     return 'admin';

        return 'guest';
    }

    function current(){
        return resolve(window.location.pathname);
    }

    return {
        resolve,
        current
    };

});