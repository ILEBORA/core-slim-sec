__BORA_REGISTER_SERVICE__('permissions', function(scope){

    const app = scope.getPlugin('AppCore');

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