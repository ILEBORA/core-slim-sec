__BORA_REGISTER_SERVICE__('uiDismissable', async function(scope){

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

    return { create };

});