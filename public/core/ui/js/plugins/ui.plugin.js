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

        formJourney.registerJourney('user.profile.edit', function ($form, done) {
            const url = $form.attr('action');
            const method = $form.attr('method') || 'POST';

            const formData = new FormData($form[0]);
            const btn = $form.find('button[type=submit]');
            const btnPrev = btn.html();
            btn.html('Processing...');

            new CallBora(url)
                .setMethod(method)
                .setParams(formData) // ✅ KEEP AS FORMDATA
                .setCallback((resp) => {

                    if (resp.success) {
                        alertBora.notify('Personal details updated', 'success', 4);

                        if (resp.redirect) {
                            appUI.content.loadPage(resp.redirect);
                        }

                        if (resp.esc) {
                            uiStack.closeTop();
                        }

                    } else {
                        alertBora.notify(resp.error || 'Action failed', 'error', 5);
                    }

                    done?.(resp);
                })
                .setError((xhr) => {
                    console.error('System error', xhr);
                    alertBora.notify('System error. Please try again later.', 'error', 15);
                    done?.(xhr);
                })
                .build();
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