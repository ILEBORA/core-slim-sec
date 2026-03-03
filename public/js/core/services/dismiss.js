__BORA_REGISTER_SERVICE__('dismiss', function(scope){

    const hooks = scope.getService('hooks');

    const stack = [];

    function register(instance){
        if(!instance) return;
        stack.push(instance);
    }

    function unregister(instance){
        const index = stack.lastIndexOf(instance);
        if(index > -1){
            stack.splice(index, 1);
        }
    }

    function top(){
        return stack[stack.length - 1] || null;
    }

    function dismissTop(){
        const instance = stack.pop();
        instance?.close?.();
    }

    // Listen globally
    hooks?.add?.('esc', dismissTop);

    return {
        register,
        unregister,
        dismissTop,
        top
    };
});