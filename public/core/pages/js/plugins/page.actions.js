__BORA_REGISTER_PLUGIN__('page.actions', async function(scope){

    const hooks = await scope.getService('hooks');
    const callbora = await scope.getService('callbora');

    /* ---------------------------------------
       Internal helper
    --------------------------------------- */

    async function open(config){

        const popup = await scope.getPlugin('popup');
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
        open({ view:'edit', id, tab:'edit', group:  'page'});
    }

    function openDuplicate(id){
        open({ view:'duplicate', id, tab:'duplicate', group:  'page', });
    }

    function openMotherPageSettings(id){
        open({ view:'settings', id, tab:'settings', group:  'page', });
    }

    function openSubpageModal(id){
        open({ view:'subpage', id, tab:'subpage', group:  'page', });
    }

    function openArrangeUI(id){
        open({ view:'arrange', id, tab:'arrange', group:  'page' });
    }

    function togglePageStatus(id){
        open({ view:'toggle', id, tab:'toggle', group:  'page', });
    }

    function confirmDelete(id){

        alertBora.prompt(
            '<h3>Confirm Action</h3>Enter your password to continue',
            {
                html: true,
                prompt: '<input type="password" name="password" placeholder="Password">'
            }
        ).then(function(det){

            overlayLoader.show('Please wait...');

            let password = btoa(det.password);

            callbora.post(`api/modules/pages/page/${id}/delete`, {
                password: password
            }).then(function(response){

                overlayLoader.hide();

                if(response.success){
                    alertBora.success('Page deleted');
                } else {
                    alertBora.error(response.message || 'Failed');
                }

            });

        });        

    }

    /* ---------------------------------------
       Hook Registration (CRITICAL)
    --------------------------------------- */

    hooks.add('pages.action', function(action, id){

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
            
            case 'duplicate':
                return openDuplicate(id);

            case 'togglestatus':
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