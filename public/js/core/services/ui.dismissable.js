__BORA_REGISTER_SERVICE__('uiDismissable', function(scope){

    const uiStack = scope.getService('uiStack');

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