__BORA_REGISTER_PLUGIN__('ActivityThread', function(scope){

    let activityId;
    let loading=false;

    function mount(){

        const el = document.querySelector('.activity-thread');
        if(!el) return;

        activityId = el.dataset.activity;

        loadActivity();
        loadComments();
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

    return { mount };

});

alert('Feed');