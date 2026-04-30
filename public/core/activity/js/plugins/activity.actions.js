__BORA_REGISTER_PLUGIN__('activity.actions', async function(scope){

    const feedUI  = await scope.getPlugin('activity.feed.ui');
    const activityComposer  = await scope.getPlugin('activity.composer');
    const uiStack = await __BORA_APP__.service('uiStack');
    const uiActions = await scope.getService('ui.actions');
    const popup = await scope.getPlugin('popup');

    const state = {
        mounted: false
    };

    function mount(){
        if (state.mounted) return;
        state.mounted = true;

        console.log('[activity.actions] mounted');
        $(document).on('click','.act-react',handleReaction);
        // $(document).off('click').on('click','.act-comment',handleComment);
        uiActions.register('act-comment',handleComment);
        $(document).on('click','.act-share', handleShare);
        $(document).on('click','.act-insights', handleInsights);
        $(document).on('click','.act-options', handleOptions);

        $(document).on('click','.act-view-media', handleMediaView);

        $(document).on('click', '.reaction-trigger', async function(e){

            e.preventDefault();

            const uiStack = await __BORA_APP__.service('uiStack');
            const dismissable = await __BORA_APP__.service('ui.dismissable');

            const $box = $(this).closest('.reaction-box');

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

        });

        $(document).on('click', '.composer-placeholder', function () {
            return openPostPopup();
        });

        $(document).on('click', '.reply-comment', handleReplies);

        $(document).on('click', '.backTo', handleBack);

        uiActions.register('popup.close', ()=>{
            uiStack.closeTop();
        });
    }

    function unmount(){
        if (!state.mounted) return;
        state.mounted = false;

        $(document).off('click','.act-react',handleReaction);
        $(document).off('click','.act-comment',handleComment);
    }

    function handleReaction(){
        const $btn = $(this);
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

    async function handleComment(el){
        // e.preventDefault();

        const id = $(el)
            .closest('.activity-item')
            .data('id');

        // const popup = await scope.getPlugin('popup');

        popup.open({
            mode:'view',
            module:'activity',
            group:'comments',
            view:'comments',
            id: id,
            tabs: [
                {
                    id: 'replies',
                    label: 'Comments',
                    url: `api/modules/activity/timeline/comments/${id}`
                },
                // {
                //     id: 'likes',
                //     label: 'Likes',
                //     url: `api/modules/activity/view/likes/${id}`
                // }
            ],

            activeTab: 'replies'
        });
    }

    function handleShare(e){
        e.preventDefault();
        const id = $(this)
            .closest('.activity-item')
            .data('id');
            // popup service
            alert('TODO:: Share '+id+' to social...');
    }

    function handleInsights(e){
        e.preventDefault();
        const id = $(this)
            .closest('.activity-item')
            .data('id');
            // popup service
            alert('TODO:: Post '+id+' insights...');
    }

    function handleOptions(e){
        e.preventDefault();
        const id = $(this)
            .closest('.activity-item')
            .data('id');
            // popup service
            alert('TODO:: Post '+id+' options...');
    }

    async function handleMediaView(e){
        e.preventDefault();
        const id = $(this)
            .data('id');

        popup.open({
            // mode:'view',
            // module:'activity',
            // group:'timeline',
            // view:'media',
            // tab:'preview',
            // id: id,
            // size:'md',
            // meta:   { id:id, mode: 'preview' },
            tabs: [
                {
                    id: 'replies',
                    label: 'Preview',
                    url: `api/modules/activity/media/preview/${id}`
                },
                {
                    id: 'edit',
                    label: 'Edit',
                    url: `api/modules/activity/media/edit/${id}`
                }
            ],

            activeTab: 'preview'
        });
        
    }

    let currentPopup = null;

    async function openPostPopup() {
        activityComposer.open();
    }

    formJourney.registerJourney('timeline.add', function($form, done) {
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
                    feedUI.addToTimeline(resp.data.html);

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

    async function handleBack(e){
        e.preventDefault();

        const activityId = $(this)
            .closest('.comment-item')
            .data('id');

        // const popup = await scope.getPlugin('popup');

        popup.open({
            mode:   'view',
            module: 'activity',
            group:  'activity',
            view:   'replies',
            id:     activityId,
            tab:    'replies',
            size:   'lg',
            meta:   {
                size: 'lg',
                state: {
                    focus: 'composer'
                }
            },
            tabs: [
                {
                    id: 'replies',
                    label: 'Replies',
                    url: `api/modules/activity/timeline/replies/${activityId}`
                },
                // {
                //     id: 'likes',
                //     label: 'Likes',
                //     url: `api/modules/activity/view/likes/${activityId}`
                // }
            ],

            activeTab: 'replies'
        });
    }

    async function handleReplies(e){
        e.preventDefault();

        const activityId = $(this)
            .closest('.comment-item')
            .data('id');

        // const popup = await scope.getPlugin('popup');

        popup.open({
            mode:   'view',
            module: 'activity',
            group:  'activity',
            view:   'replies',
            id:     activityId,
            tab:    'replies',
            size:   'lg',
            meta:   {
                size: 'lg',
                state: {
                    focus: 'composer'
                }
            },
            tabs: [
                {
                    id: 'replies',
                    label: 'Replies',
                    url: `api/modules/activity/timeline/replies/${activityId}`
                },
                // {
                //     id: 'likes',
                //     label: 'Likes',
                //     url: `api/modules/activity/view/likes/${activityId}`
                // }
            ],

            activeTab: 'replies'
        });
    }
    


    return { mount, unmount };

},{
    activateOn: (route) => route.startsWith('portal/activity')
});