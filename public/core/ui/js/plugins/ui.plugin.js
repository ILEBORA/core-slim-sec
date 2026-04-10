__BORA_REGISTER_PLUGIN__('ui.plugin', async function(scope){

    const hooks = await scope.getService('hooks');
    const callbora   = await scope.getService('callbora');
    const dismissable = await scope.getService('ui.dismissable');
    const uiActions = await scope.getService('ui.actions');
    const popup = await scope.getPlugin('popup');
    const prefs = await scope.getService('preferences');


    const state = {
        mounted: false
    };

    function mount(){
        if (state.mounted) return;
        state.mounted = true;

        console.log('[UI Plugin] mounted...');

        uiBind();
    }

    function unmount(){
        if (!state.mounted) return; //FIXED (was wrong)
        state.mounted = false;

        uiUnbind();
    }

    function uiBind(){
        uiActions.register('ui.open.language.selector', async () => {
            await prefs.loadLanguages();

            popup.open({
                mode:'view',
                module:'ui',
                group:'languages',
                view:'languages',
                id: null,
                content: prefs.renderLanguageList(),
                tabs: [
                    {
                        id: 'languages',
                        label: 'Select Language',
                        url: `api/modules/ui/languages/choose`,
                        // content: prefs.renderLanguageList()
                    },
                    // {
                    //     id: 'likes',
                    //     label: 'Likes',
                    //     url: `api/modules/activity/view/likes/${id}`
                    // }
                ],

                activeTab: 'languages',
                meta: {
                    size: 'md'
                }
            });

        });

        uiActions.register('ui.change.language', async (el) => {
            const lang = $(el).data('lang');

            if ($(el).hasClass('active')) return;
            
            await prefs.set('language', lang);
            // await prefs.apply();   

            // location.reload();
        });
    }

    function uiUnbind(){
        uiActions.unregister('ui.open.language.selector');
    }

    return {
        mount,
        unmount
    };

});