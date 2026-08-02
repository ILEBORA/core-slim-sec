__BORA_REGISTER_SERVICE__('ui.stack', async function(scope){

    const stack = [];

    function register(instance){

        if(!instance) return;

        stack.push(instance);

        return instance;
    }

    function unregister(instance){

        const index = stack.lastIndexOf(instance);

        if(index > -1){
            stack.splice(index,1);
        }
    }

    function top(){
        return stack[stack.length - 1] || null;
    }

    function closeTop(){
        console.trace("uiStack.closeTop");
        const instance = stack.pop();

        if(!instance) return;

        if(typeof instance.close === 'function'){
            instance.close();
        }
    }

    function size(){
        return stack.length;
    }

    /* GLOBAL ESC HANDLER */

    document.addEventListener('keydown', function(e){

        if(e.key !== 'Escape') return;

        closeTop();
    });

    return {
        register,
        unregister,
        closeTop,
        top,
        size
    };

});