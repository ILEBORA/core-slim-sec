__BORA_REGISTER_PLUGIN__('users.actions', async function(scope){

    const callbora = await scope.getService('callbora');
    const feedUI  = await scope.getPlugin('activity.workspace');
    const activityComposer  = await scope.getPlugin('activity.composer');
    const uiStack = await scope.getService('ui.stack');
    const uiActions = await scope.getService('ui.actions');
    const forms = await scope.getService('forms');

    const dismissable = await scope.getService('ui.dismissable');
    const bNavigator = await scope.getService('navigator');

    const state = {
        mounted: false,
        initialized:false
    };

    function mount(){
        if (state.mounted) return;
        state.mounted = true;
        // alert('Users Actions Mounted');
        init();
    }

    function unmount(){
        if (!state.mounted) return;
        state.mounted = false;
        state.initialized = false;
    }


    function init(){
        if (state.initialized) return;
        state.initialized = true;

        console.log('[users.actions] mounted');

        uiActions.register('users.seed.startTask', startSeedTask);

    }
    
    async function startSeedTask(el) {

        const taskUid = $(el).data('task-uid');;
    
        if (!taskUid) {
            console.error('Missing seed task UID');
            return;
        }
    
        $(el).addClass('is-loading');
    
        try {
    
            callbora.post(`api/modules/users/seedtasks/start`, {
                task_uid: taskUid
            }).then(function(response){
                if(response.success){
                    alertBora.success('Redirectingt to task...');

                    //remove item
                    
                    
                    // scope.emit('timeline.back');

                    if (response.redirect) {
                        appUI.content.loadPage(response.redirect);
                    }

                } else {
                    alertBora.error(response.message || 'Failed');
                }

            });

            // const resp = await api.post(
            //     'api/modules/users/seedtasks/start',
            //     {
            //         task_uid: taskUid
            //     }
            // );
    
            // if (!resp.success) {
            //     // throw new Error(
            //     //     response.message || 'Unable to start task'
            //     // );
            //     alertBora.notify(resp.message || 'Unable to start task', 'error', 5);
            // }
    
            // /*
            //  * Only navigate AFTER the state transition succeeds.
            //  */
            // navigate(resp.redirect);
    
        } catch (error) {
    
            alertBora.notify(error || '[SEED] Failed to start task', 'error', 5);

            console.error(
                '[SEED] Failed to start task',
                error
            );
    
            $(el).removeClass('is-loading');
    
            /*
             * Show your normal UI error.
             */
        }
    }
    
    return { mount, unmount };

}
);