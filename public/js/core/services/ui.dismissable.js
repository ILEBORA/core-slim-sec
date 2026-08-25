__BORA_REGISTER_SERVICE__('ui.dismissable', async function(scope){

    const uiStack = await scope.getService('ui.stack');

    function create(closeFn){

        let closed = false;
    
        const instance = {
    
            close(){
    
                if(closed){
                    return true;
                }
    
                closed = true;
    
                uiStack.unregister(instance);
    
                closeFn?.();
                // alert('hee');
                return true;
            },
            handlesEscape: true
    
        };
    
        uiStack.register(instance);
    
        return instance;
    
    }

    function createOW(closeFn){

        let closed = false;
    
        const instance = {
    
            close(){
    
                if(closed) return;
    
                closed = true;
    
                closeFn?.();
    
                uiStack.unregister(instance);
    
            },
    
            destroy(){
    
                if(closed) return;
    
                closed = true;
    
                uiStack.unregister(instance);
    
            }
    
        };
    
        uiStack.register(instance);
    
        return instance;
    
    }

    function createO(closeFn){

        const instance = {

            close(){
                console.trace("dismissable.close");
                closeFn();
                uiStack.unregister(instance);
            }

        };

        uiStack.register(instance);

        return instance;
    }

    function destroy(){
        uiStack.unregister(instance);
    }

    return { create, destroy };

});