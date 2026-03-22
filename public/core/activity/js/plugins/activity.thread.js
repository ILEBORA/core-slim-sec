__BORA_REGISTER_PLUGIN__('activity.thread', async function(scope){

    const utils  = await scope.getService('activity.utils');

    let activityId;
    let loading=false;

    function init(){
        loadActivity();
        bind();
    }

    function bind(){

        $('#threadSendComment').on('click', sendComment);
    }

    function sendComment(){

        const body = $('#threadCommentBody').val().trim();
        if(!body) return;

        $.post('api/modules/activity/comment',{
            activity_id:activityId,
            body
        }).done(()=>{
            $('#threadCommentBody').val('');
            loadComments();
        });
    }

    function loadActivity(){

        $.getJSON('api/modules/activity/get',{id:activityId})
        .done(resp=>{
            if(!resp.ok) return;

            $('#threadActivity').html(resp.data.html);
            const el = document.querySelector('.activity-thread');
            if(!el) return;

            activityId = el.dataset.activity;
            // alert(activityId);

            loadComments();
        });
    }

    function loadComments(){

        if(loading) return;
        loading=true;

        $.getJSON('api/modules/activity/comments',{
            activity_id:activityId
        }).done(resp=>{

            if(!resp.ok) return;

            const $list = $('#threadComments').empty();

            resp.data.forEach(c=>{
                $list.append(renderCommentTree(c));
            });

        }).always(()=>{
            loading=false;
        });
    }

    function renderCommentTree(comment, depth = 0) {
        const $el = $(renderComment(comment, depth));

        if (comment.replies && comment.replies.length) {
            const $replies = $('<div class="comment-replies"></div>');

            comment.replies.forEach(reply => {
                $replies.append(renderCommentTree(reply, depth + 1));
            });

            $el.append($replies);
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
                        <span class="time">${utils.timeAgo(c.created_at)}</span>
                    </div>

                    <div class="comment-text">
                        ${utils.renderMentions(utils.renderHashtags(c.body))}
                    </div>

                    <div class="comment-actions">
                        <a href="#" class="reply-comment" data-id="${c.id}">Reply</a>
                    </div>
                </div>
            </div>
        `;
    }

    return { init };

});