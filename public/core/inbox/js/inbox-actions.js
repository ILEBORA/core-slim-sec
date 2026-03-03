__BORA_REGISTER_SERVICE__('inbox.actions', function(scope){

    const hooks = scope.getService('hooks');

    document.addEventListener('click', function(e){

        const btn = e.target.closest('[data-action="inbox:start"]');
        if(!btn) return;

        const inbox = window.__BORA_APP__?.plugin('Inbox');
        inbox?.startConversation?.();

    });

});