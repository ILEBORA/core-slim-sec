__BORA_REGISTER_PLUGIN__('activity.actions', async function(scope){

    const callbora = await scope.getService('callbora');
    const feedUI  = await scope.getPlugin('activity.workspace');
    const activityComposer  = await scope.getPlugin('activity.composer');
    const uiStack = await __BORA_APP__.service('uiStack');
    const uiActions = await scope.getService('ui.actions');
    const popup = await scope.getPlugin('popup');
    const routeRegistry = await scope.getService('route.registry');

    const dismissable = await __BORA_APP__.service('ui.dismissable');
    const bNavigator = await scope.getService('navigator');

    const state = {
        mounted: false,
        initialized:false
    };

    function mount(){
        if (state.mounted) return;
        state.mounted = true;
        // alert('Activity Actions Mounted');
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

        console.log('[activity.actions] mounted');

        //popups
        uiActions.register('act-comment',popupComment);
        uiActions.register('reply-comment', popupReplies);
        uiActions.register('act-timeline-composer', popupTimelineComposer);

        //
        uiActions.register('act-back-to-post',handleBacktoPost);

        

        // acttion buttons
        uiActions.register('act-react', handleReaction);
        uiActions.register('act-share', handleShare);
        uiActions.register('act-insights', handleInsights);
        uiActions.register('act-options', handleOptions);

        //views
        uiActions.register('reaction-trigger', showReactions);
        uiActions.register('act-view-reactions', showReactionsView);
        uiActions.register('act-view-media', showMediaView);

        //Options
        uiActions.register('activity.delete', handleDelete);
        uiActions.register('activity.restore', handleRestore);
        uiActions.register('activity.force-delete', handleForceDelete);
        uiActions.register('activity.edit', popupEdit);
        uiActions.register('activity.export', handleExport);
        uiActions.register('activity.details', showDetailsView);

        uiActions.register('popup.close', ()=>{
            uiStack.closeTop();
        });

        // media options
        uiActions.register('act-remove-media', activityComposer.handleRemoveMedia);
        uiActions.register('act-rotate-media', activityComposer.handleRotateMedia);

        //Share
        uiActions.register('activity.share.whatsapp', (el)=>{
            const url = $(el).data('url');
            window.open(`https:\/\/wa.me\/?text=${encodeURIComponent(url)}`,
                '_blank'
            );
        });

        uiActions.register('activity.share.telegram', (el)=>{
            const url = $(el).data('url');
            window.open(`https:\/\/t.me\/share\/url?url=${encodeURIComponent(url)}`,
                '_blank'
            );
        });

        uiActions.register('activity.share.copylink', (el)=>{
            const url = $(el).data('url');

            navigator.clipboard
                .writeText(url)
                .then(()=>{

                    alertBora.success('Link copied');

                });
        });

        uiActions.register('activity.share.native', async (el)=>{
            const url = $(el).data('url');

            if(navigator.share){
                await navigator.share({
                    title: 'Shared Post',
                    url
                });

                return;
            }

            copyShareLink(url);

        });

        uiActions.register('activity.share.timeline', (el)=>{
            const id = $(el).data('id');
            
            bNavigator.go({
                route: 'activity.share.timeline',
                params: { id },
                surface: 'popup'
            });
        });

    }

    async function showReactions(el){
        const id = $(el)
            .closest('.activity-item')
            .data('id');

        const $box = $(`.reaction-box[data-id="${id}"]`);

        if($box.hasClass('open')){
            $box.data('dismissInstance')?.close();
            return;
        }


        // close any other dropdown
        uiStack.closeTop();

        $box.addClass('open');

        const instance = dismissable.create(()=>{
            $box.removeClass('open');
            $box.removeData('dismissInstance');
        });

        $box.data('dismissInstance', instance);

    }

    function handleReaction(el){
        const $btn = $(el);
        const reaction = $btn.data('reaction');

        const $item = $btn.closest('.activity-item');
        const id = $item.data('id');

        const $box = $item.find('.reaction-box');
        // close dropdown
        $box.data('dismissInstance')?.close();

        // optimistic trigger update
        $item.find('.reaction-trigger').text($btn.text());

        $.post('api/modules/activity/react',{
            activity_id: id,
            reaction
        }).done(function(resp){
            if(!resp?.data?.html) return;

            $item.find('.reaction-summary')
                .replaceWith(resp.data.html);
        });

    }

    async function popupComment(el){

        const id = $(el)
            .closest('.activity-item')
            .data('id');

        if (!id) return;

        bNavigator.go({
            route: 'activity.comments',
            params: { id, tab: 'replies' },
            surface: 'popup'
        });
    }

    async function popupEdit(el){
        const id = $(el)
            // .closest('.activity-item')
            .data('id');
        alert(id);

        if (!id) return;

        bNavigator.go({
            route: 'activity.edit',
            params: { id, tab: 'edit' },
            surface: 'popup'
        });
    }

    async function handleBacktoPost(el){
        const id = $(el).data('id');

        bNavigator.go({
            route: 'activity.comments',
            params: { id, tab: 'replies' },
            surface: 'popup'
        });
    }

    async function handleShare(el){

        const id = $(el)
            .closest('.activity-item')
            .data('id');

        if (!id) return;

        bNavigator.go({
            route: 'activity.share.options',
            params: {
                id
            },
            surface: 'popup'
        });

    }

    function handleInsights(el){
        const id = $(el)
            .closest('.activity-item')
            .data('id');
            // popup service
            alert('TODO:: Post '+id+' insights...');
    }

    function handleOptions(el){
        const id = $(el)
            .closest('.activity-item')
            .data('id');
            // popup service
            alert('TODO:: Post '+id+' options...');
    }

    function handleExport(el){
        const id = $(el)
            .closest('.activity-item')
            .data('id');
            // popup service
            alert('TODO:: Post '+id+' export...');
    }

    async function showReactionsView(el){
        const id = $(el)
            .data('id');
        
        if (!id) return;

        bNavigator.go({
            route: 'activity.details',
            params: { id, tab: 'reactions' },
            surface: 'popup'
        });
    }

    async function showMediaView(el){
        const id = $(el)
            .data('id');
        
        if (!id) return;

        bNavigator.go({
            route: 'activity.media',
            params: { id, tab: 'preview' },
            surface: 'popup'
        });
    }

    async function showDetailsView(el){
        const id = $(el)
            .data('id');
        
        if (!id) return;

        bNavigator.go({
            route: 'activity.details',
            params: { id, tab: 'details' },
            surface: 'popup'
        });
    }

    

    async function popupTimelineComposer() {
        activityComposer.open();
    }

    formJourney.registerJourney('timeline.add', function($form, done) {
        const url = $form.attr('action');
        const method = $form.attr('method') || 'POST';
        const btn = $form.find('button[type=submit]');
        const prevtext = btn.text();
        btn.prop('disabled', true).text('Processing...');
        
        //
        const values = $form.find('.select2-ajax').val() || [];

        const invalid = values.filter(v => v.startsWith('__new__:'));

        if (invalid.length) {
            e.preventDefault();
            alert('Please select valid people from the list.');
            return false;
        }
        //

        // If files exist, use FormData; otherwise fallback to serialize
        let hasFiles = $form.find('input[type="file"]').length > 0;
        let data = null;
        let ajaxOptions = {
            url,
            method,
            success(resp){
                if(resp.success){
                    //Add to timeline
                    feedUI?.addToTimeline(resp.data.html);

                    alertBora.notify('Post Shared', 'success', 4);
                    if(resp.redirect){
                        if(typeof authChannel !== 'undefined'){
                            authChannel.postMessage({cmd:'login', usr: rd('bID'), lnk: resp.redirect});
                        }
                        redirectTo(resp.redirect);
                    }
                    
                    if(resp.esc){
                        uiStack.closeTop();
                    }

                    btn.prop('disabled', false).text(prevtext);
                    
                } else {
                    alertBora.notify(resp.message || 'Unexpected error', 'error', 5);
                    btn.prop('disabled', false).text(prevtext);
                }
                if(typeof done === 'function') done(resp);

                // Remove attachments from cache
                activityComposer.reset();
            },
            error(err){
                btn.prop('disabled', false).text(prevtext);
                alertBora.notify('Network / Server error', 'error', 5);
                if(typeof done === 'function') done(err);
            }
        };

        if(hasFiles){
            data = new FormData($form[0]);
            ajaxOptions.data = data;
            ajaxOptions.processData = false;
            ajaxOptions.contentType = false;
        } else {
            data = $form.serialize();
            ajaxOptions.data = data;
        }

        $.ajax(ajaxOptions);
    });

    formJourney.registerJourney('stories.add', function($form, done) {
        const url = $form.attr('action');
        const method = $form.attr('method') || 'POST';
        const btn = $form.find('button[type=submit]');
        const prevtext = btn.text();
        btn.prop('disabled', true).text('Processing...');

        // If files exist, use FormData; otherwise fallback to serialize
        let hasFiles = $form.find('input[type="file"]').length > 0;
        let data = null;
        let ajaxOptions = {
            url,
            method,
            success(resp){
                if(resp.success){
                    //Add to timeline
                    // feedUI.addToTimeline(resp.data.html);

                    alertBora.notify('Post Shared', 'success', 4);
                    if(resp.redirect){
                        if(typeof authChannel !== 'undefined'){
                            authChannel.postMessage({cmd:'login', usr: rd('bID'), lnk: resp.redirect});
                        }
                        redirectTo(resp.redirect);
                    }
                    
                    if(resp.esc){
                        uiStack.closeTop();
                    }

                    btn.prop('disabled', false).text(prevtext);
                    
                } else {
                    alertBora.notify(resp.message || 'Unexpected error', 'error', 5);
                    btn.prop('disabled', false).text(prevtext);
                }
                if(typeof done === 'function') done(resp);
            },
            error(err){
                btn.prop('disabled', false).text(prevtext);
                alertBora.notify('Network / Server error', 'error', 5);
                if(typeof done === 'function') done(err);
            }
        };

        if(hasFiles){
            data = new FormData($form[0]);
            ajaxOptions.data = data;
            ajaxOptions.processData = false;
            ajaxOptions.contentType = false;
        } else {
            data = $form.serialize();
            ajaxOptions.data = data;
        }

        $.ajax(ajaxOptions);
    });

    async function popupReplies(el){

        const id = $(el)
            .data('id');
        const parent = $(el)
            .closest('.activity-thread')
            .data('id');
        
        if (!id || !parent) return;

        bNavigator.go({
            route: 'activity.replies',
            params: { id, parent, tab: 'replies' },
            surface: 'popup'
        });
    }

    //
    async function handleDelete(el){
        let activityId = $(el).data('id');

        alertBora.prompt(
            '<h3>Confirm Action</h3>Enter your password to continue',
            {
                html: true,
                prompt: '<input type="password" name="password" placeholder="Password">'
            }
        ).then(function(det){

            let password = btoa(det.password);

            callbora.post(`api/modules/activity/timeline/${activityId}/delete`, {
                password: password
            }).then(function(response){
                if(response.success){
                    alertBora.success('Activity soft deleted');

                    //remove item
                    $('.activity-item[data-id"'+activityId+'"]').addClass('deleted');
                    
                    scope.emit('people.back');

                } else {
                    alertBora.error(response.message || 'Failed');
                }

            });

        }); 

    }

    async function handleRestore(el){
        let activityId = $(el).data('id');

        alertBora.prompt(
            '<h3>Confirm Action</h3>Enter your password to continue',
            {
                html: true,
                prompt: '<input type="password" name="password" placeholder="Password">'
            }
        ).then(function(det){

            let password = btoa(det.password);

            callbora.post(`api/modules/activity/timeline/${activityId}/restore`, {
                password: password
            }).then(function(response){

                if(response.success){
                    alertBora.success('Activity restore');

                    //Restore item
                    $('.activity-item[data-id"'+activityId+'"]').removeClass('deleted');

                    if(response.redirect){
                        navigation.go(response.redirect);
                    }
                    
                } else {
                    alertBora.error(response.message || 'Failed');
                }

            });

        }); 

    }

    async function handleForceDelete(el){
        let activityId = $(el).data('id');

        alertBora.prompt(
            '<h3>Confirm Action</h3>Enter your password to continue',
            {
                html: true,
                prompt: '<input type="password" name="password" placeholder="Password">'
            }
        ).then(function(det){

            let password = btoa(det.password);

            callbora.post(`api/modules/activity/timeline/${activityId}/forcedelete`, {
                password: password
            }).then(function(response){

                if(response.success){
                    alertBora.success('Person deleted');

                    //remove item
                    $('.activity-item[data-id"'+activityId+'"]').remove();

                    scope.emit('people.back');
                } else {
                    alertBora.error(response.message || 'Failed');
                }

            });

        }); 

    }

    

    function copyShareLink(url){
        navigator.clipboard
            .writeText(url)
            .then(()=>{
                alertBora.success('Link copied');
            });
    }

    


    
    return { mount, unmount };

},
// {
//     // activateOn: (route) => route.startsWith('portal/activity')
// }
);