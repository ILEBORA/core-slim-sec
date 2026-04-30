__BORA_REGISTER_PLUGIN__('activity.thread', async function(scope){

    const utils  = await scope.getService('activity.utils');
    const uiActions = await scope.getService('ui.actions');
    const callbora = await scope.getService('callbora');

    // let activityId;
    // let parentId;
    let loading=false;
    const state = {
        mounted: false
    };

    function init(id){
        // if (state.mounted) return;
        // state.mounted = true;
        
        // loadActivity(id);
         const el = document.querySelector('.activity-thread');

        if(!el) return;

        activityId = el.dataset.id;
        parentId = el.dataset.parent;
        // alert(activityId);

        loadComments(activityId, parentId);
        
        bind();
    }

    function bind(){
        // $('#threadSendComment').off().on('click', sendComment);
        uiActions.register('thread.send.comment', sendComment)
    }

    function sendComment(el){
        const activity = $(el).closest('.activity-thread');
        const activityId = activity.data('id');
        const parentId = activity.data('parent');
        const body = $('#threadCommentBody').val().trim();
        
        if(!body){ 
            $('#threadCommentBody').focus();
            return;
        }

        callbora.post(`api/modules/activity/comment`, {
            activity_id:activityId,
            parent_id: parentId,
            body
        }).then(function(res){
            if(res.success){
                alertBora.success(res.message|| 'Success');
                $('#threadCommentBody').val('');
                loadComments(activityId, parentId);
            } else {
                alertBora.error(res.message || 'Failed');
            }

            state.mounted = false;
        });
    }

    function loadActivity(id){
        // alert(id);
        $.getJSON('api/modules/activity/get',{id:id})
        .done(resp=>{
            if(!resp.success) return;

            $('#threadActivity').html(resp.data.html);

            const el = document.querySelector('.activity-thread');

            if(!el) return;

            activityId = el.dataset.id;
            parentId = el.dataset.parent;
            // alert(activityId);

            loadComments(activityId, parentId);
        });
    }

    function loadComments(activityId, parentId){

        if(loading) return;
        loading=true;
        // alert(activityId+' :: '+parentId);
        $.getJSON('api/modules/activity/comments',{
            activity_id:activityId,
            parent_id:parentId
        }).done(resp=>{

            if(!resp.success) return;

            const $list = $('#threadComments').empty();

            resp.data.forEach(c=>{
                $list.append(renderCommentTree(c));
            });

        }).always(()=>{
            loading=false;
        });
    }

    function renderCommentTree(comment, depth = 0) {
        // alert('renderCommentTree');
        const $el = $(renderComment(comment, depth));

        if (comment.replies && comment.replies.length) {
            // const $replies = $('<div class="comment-replies"></div>');
            const $replies = $($el).find('.comment-replies');

            comment.replies.forEach(reply => {
                $replies.append(renderCommentTree(reply, depth + 1));
            });

            // $el.append($replies);
        }

        return $el;
    }


    function renderComment(c, depth = 0) {
        return `
            <div class="comment-item" data-id="${c.id}" style="margin-left:${depth * 20}px">
                <div class="comment-avatar">
                    <img src="${c.actor.avatar || '/img/avatar.png'}">
                </div>

                <div class="comment-body">
                    <div class="comment-meta">
                        <strong>@${c.actor.username}</strong>
                        <span class="time">${c.timeago_format}</span>
                    </div>

                    <div class="comment-text">
                        ${utils.renderMentions(utils.renderHashtags(c.body))}
                    </div>

                    <div class="comment-actions">
                        <a href="#" class="reply-comment" data-id="${c.id}">Reply</a>
                    </div>

                    <div class="comment-replies"></div>
                </div>
            </div>
        `;
    }

    return { init };

});