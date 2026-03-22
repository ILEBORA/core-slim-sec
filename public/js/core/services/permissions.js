__BORA_REGISTER_SERVICE__('permissions', async function(scope){

    const app = await scope.getPlugin('appcore');

    function can(group, sub){
        return app?.hasPermission(group, sub) === true;
    }

    function guardElement(el, group, sub){

        if(!can(group,sub)){
            el.remove();
            return false;
        }

        return true;
    }

    return { can, guardElement };

});