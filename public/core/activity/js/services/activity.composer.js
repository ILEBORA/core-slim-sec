__BORA_REGISTER_SERVICE__('activity.composer', function(scope){

    const popup = scope.getService('popup');

    function open(){

        popup.open({
            mode:'form',
            module:'activity',
            group:'timeline',
            view:'add',
            tab:'add',
            size:'md'
        });

    }

    return { open };

});