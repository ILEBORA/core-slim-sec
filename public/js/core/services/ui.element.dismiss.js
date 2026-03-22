__BORA_REGISTER_SERVICE__('uiElementDismiss', async function(scope){

    const dismissable = await scope.getService('uiDismissable');

    function bind($el, openClass='open'){

        if($el.data('dismissInstance')) return;

        const instance = dismissable.create(()=>{
            $el.removeClass(openClass);
            $el.removeData('dismissInstance');
        });

        $el.addClass(openClass);
        $el.data('dismissInstance', instance);

        return instance;
    }

    return { bind };

});