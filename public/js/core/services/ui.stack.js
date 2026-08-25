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

    let closing = false;
    function closeTop(){
        if(closing){
            return;
        }
    
        closing = true;

        try{

            const instance = top();
        
            if(!instance) return false;
        
            if(typeof instance.close !== 'function'){
                return false;
            }
        
            instance.close();
        }
        finally{

            setTimeout(() => {

                closing = false;

            },0);

        }
    
        return true;
    }

    function closeTopO(){
        console.trace("uiStack.closeTop");
        const instance = stack.pop();

        if(!instance) return;

        if(instance.handlesEscape === false){
            return false;
        }

        if(typeof instance.close === 'function'){
            instance.close();
        }

        return true;
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