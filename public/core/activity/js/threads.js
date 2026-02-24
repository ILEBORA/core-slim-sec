alert('thread');
const Thread = {
    activityId: null,
    loading: false,

    init($activity = true) {
        this.activityId = $('.activity-thread').data('activity');
        if($activity){
            this.loadActivity();
        }else{
            this.loadComments();
        }
        this.loadComments();
        this.bind();
    },

    loadActivity() {
        $.getJSON('api/modules/activity/get', {
            id: this.activityId
        }).done(resp => {
            if (!resp.ok) return;
            $('.activity-thread').find('#threadActivity').html(renderThreadActivity(resp.data));
        });
    },

    loadComment() {
        $.getJSON('api/modules/activity/getcomment', {
            id: this.activityId
        }).done(resp => {
            if (!resp.ok) return;
            $('.activity-thread').find('#threadActivity').html(renderThreadComment(resp.data));
        });
    },

    loadComments() {
        if (this.loading) return;
        this.loading = true;

        $.getJSON('api/modules/activity/comments', {
            activity_id: this.activityId
        }).done(resp => {
            if (!resp.ok) return;

            const $list = $('#threadComments').empty();
            resp.data.forEach(c => {
                $list.append(renderCommentTree(c));
            });
        }).always(() => {
            this.loading = false;
        });
    },

    bind() {
        $('#threadSendComment').on('click', () => {
            const body = $('#threadCommentBody').val().trim();
            if (!body) return;

            $.post('api/modules/activity/comment', {
                activity_id: this.activityId,
                body
            }).done(() => {
                $('#threadCommentBody').val('');
                this.loadComments(); // later: optimistic insert
            });
        });
    }
};

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
                    <span class="time">${timeAgo(c.created_at)}</span>
                </div>

                <div class="comment-text">
                    ${renderMentions(renderHashtags(c.body))}
                </div>

                <div class="comment-actions">
                    <a href="#" class="reply-comment" data-id="${c.id}">Reply</a>
                </div>
            </div>
        </div>
    `;
}

function renderThreadActivity(item) {
    console.log(item);
    return item.html;
    return `
        <div class="thread-activity" data-id="${item.id}">
            <div class="thread-actor">
                <img class="avatar"
                     src="${item.actor.avatar || '/img/avatar.png'}"
                     alt="${item.actor.username}">
            </div>

            <div class="thread-content">
                <div class="thread-meta">
                    <strong>@${item.actor.username}</strong>
                    <span class="time">${timeAgo(item.created_at)}</span>
                </div>

                <div class="thread-body">
                    ${renderMentions(renderHashtags(item.body || ''))}
                </div>

                ${renderThreadSnapshot(item)}

                <div class="thread-stats">
                    <span>${item.comments_count || 0} comments</span>
                </div>
            </div>
        </div>
    `;
}

function renderThreadSnapshot(item) {
    if (!item.payload || !item.payload.snapshot) return '';

    const snap = item.payload.snapshot;

    return `
        <div class="thread-snapshot">
            <img src="${snap.image}" alt="">
        </div>
    `;
}

function renderThreadComment(item) {
    console.log(item);
    return item.html;
    return `
        <div class="thread-activity" data-id="${item.id}">
            <div class="thread-actor">
                <img class="avatar"
                     src="${item.actor.avatar || '/img/avatar.png'}"
                     alt="${item.actor.username}">
            </div>

            <div class="thread-content">
                <div class="thread-meta">
                    <strong>@${item.actor.username}</strong>
                    <span class="time">${timeAgo(item.created_at)}</span>
                </div>

                <div class="thread-body">
                    ${renderMentions(renderHashtags(item.body || ''))}
                </div>

                ${renderThreadSnapshot(item)}

                <div class="thread-stats">
                    <span>${item.comments_count || 0} comments</span>
                </div>
            </div>
        </div>
    `;
}