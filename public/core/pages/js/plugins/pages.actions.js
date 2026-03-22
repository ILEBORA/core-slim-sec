__BORA_REGISTER_PLUGIN__('pages.actions', async function(scope){

    const hooks = await scope.getService('hooks');
    



    

    /* ---------------------------------------
       Internal helper
    --------------------------------------- */

    async function open(config){

        const popup = await scope.getService('popup');
        if(!popup) return;

        popup.open({
            mode:   'form',
            module: 'pages',
            group:  'manage',
            size:   'md',
            meta:   null,
            ...config
        });
    }

    /* ---------------------------------------
       Actions
    --------------------------------------- */

    function openPageEditor(id){
        open({ view:'edit', id, tab:'edit' });
    }

    function openMotherPageSettings(id){
        open({ view:'settings', id, tab:'settings' });
    }

    function openSubpageModal(id){
        open({ view:'subpage', id, tab:'subpage' });
    }

    function openArrangeUI(id){
        open({ view:'arrange', id, tab:'arrange' });
    }

    function togglePageStatus(id){
        open({ view:'toggle', id, tab:'toggle' });
    }

    function confirmDelete(id){

        alertBora.confirm('Are you <em>really</em> sure?', { html:true })
        .autoCancel(20)
        .then(function(){
            console.warn('Delete not implemented:', id);
        }, function(){
            console.log('Delete cancelled');
        });

    }

    /* ---------------------------------------
       Hook Registration (CRITICAL)
    --------------------------------------- */

    hooks.register('pages.action', function(action, id){

        switch(action){

            case 'edit':
                return openPageEditor(id);

            case 'settings':
                return openMotherPageSettings(id);

            case 'add-subpage':
                return openSubpageModal(id);

            case 'arrange':
                return openArrangeUI(id);

            case 'toggle-status':
                return togglePageStatus(id);

            case 'delete':
                return confirmDelete(id);

        }

    });

    return {
        openPageEditor,
        openMotherPageSettings,
        openSubpageModal,
        openArrangeUI,
        togglePageStatus,
        confirmDelete
    };

});