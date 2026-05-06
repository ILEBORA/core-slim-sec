__BORA_REGISTER_SERVICE__('uid', function(){

    function generate(prefix = 'id'){
        return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2,6)}`;
    }

    return { generate };
});