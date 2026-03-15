__BORA_REGISTER_PLUGIN__('ActivityActions', function(scope){

    const feedUI  = scope.getPlugin('ActivityFeedUI');
    const activityComposer  = scope.getPlugin('ActivityComposer');

    function mount(){

        $(document).on('click','.act-react',handleReaction);
        $(document).on('click','.act-comment',handleComment);
        $(document).on('click','.act-share', handleShare);
        $(document).on('click','.act-insights', handleInsights);
        $(document).on('click','.act-options', handleOptions);

        $(document).on('click','.act-view-media', handleMediaView);

        $(document).on('click', '.reaction-trigger', function(e){

            e.preventDefault();

            const uiStack = __BORA_APP__.service('uiStack');
            const dismissable = __BORA_APP__.service('uiDismissable');

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
    }

    function unmount(){

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

    function handleComment(e){
        e.preventDefault();

        const id = $(this)
            .closest('.activity-item')
            .data('id');

        const popup = window.__BORA_APP__?.service('popup');

        popup?.open({
            mode:'view',
            module:'activity',
            group:'comments',
            view:'comments',
            id: id
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

    function handleMediaView(e){
        e.preventDefault();
        const id = $(this)
            .data('id');

        const popup = scope.getService('popup');

        popup.open({
            mode:'view',
            module:'activity',
            group:'timeline',
            view:'media',
            tab:'preview',
            id: id,
            size:'md',
            meta:   { id:id, mode: 'preview' }
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
                        setTimeout(()=>{
                            __BORA_APP__.service('uiStack')?.closeTop();
                        },0);
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

    function handleReplies(e){
        e.preventDefault();

        const activityId = $(this)
            .closest('.comment-item')
            .data('id');

        // mPGs.klassView(
        //     'Activity',
        //     'replies',
        //     activityId,
        //     {
        //         size: 'lg',
        //         state: {
        //             focus: 'composer'
        //         }
        //     }
        // );

        const popup = window.__BORA_APP__?.service?.('popup');
        if (!popup) return;

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
            }
        });
    }
    


    return { mount, unmount };

});