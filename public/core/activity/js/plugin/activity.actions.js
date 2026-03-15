__BORA_REGISTER_PLUGIN__('ActivityActions', function(scope){

    function mount(){

        $(document).on('click','.act-react',handleReaction);
        $(document).on('click','.act-comment',handleComment);
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

        $.post('api/modules/activity/react',{
            activity_id:id,
            reaction
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
            id
        });
    }

    return { mount, unmount };

});

alert('Activity Actions');