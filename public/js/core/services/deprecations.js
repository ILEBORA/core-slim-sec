__BORA_REGISTER_SERVICE__('deprecations', function(scope){

    const config = scope.config || {};
    const warned = new Set();

    function warn(key, message){

        if(!config.dev) return;

        if(warned.has(key)) return;

        warned.add(key);

        console.warn(
            `%c[Bora Deprecated]%c ${message}`,
            'color:orange;font-weight:bold;',
            'color:inherit;'
        );
    }

    function hasWarned(key){
        return warned.has(key);
    }

    function reset(){
        warned.clear();
    }

    return {
        warn,
        hasWarned,
        reset
    };
});