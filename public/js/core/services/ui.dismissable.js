__BORA_REGISTER_SERVICE__('ui.dismissable', async function(scope){

    const uiStack = await scope.getService('uiStack');

    function create(closeFn){

        const instance = {

            close(){
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