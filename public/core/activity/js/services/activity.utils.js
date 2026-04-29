__BORA_REGISTER_SERVICE__('activity.utils', function(){

    function renderMentions(text){
        return text.replace(
            /@([a-zA-Z0-9_.]{3,30})/g,
            '<a href="portal/people/person/$1/view" class="mention">@$1</a>'
        );
    }

    function renderHashtags(text){
        return text.replace(
            /#([a-zA-Z0-9_]{2,50})/g,
            '<a href="portal/activity/hashtag/$1" class="hashtag">#$1</a>'
        );
    }

    function timeAgo(ts) {
        const now = Date.now() / 1000;  // convert ms → seconds
        const seconds = Math.floor(now - ts);

        if (seconds < 60) return 'just now';
        if (seconds < 3600) return Math.floor(seconds / 60) + 'm';
        if (seconds < 86400) return Math.floor(seconds / 3600) + 'h';
        return Math.floor(seconds / 86400) + 'd';
    }


    return {
        renderMentions,
        renderHashtags,
        timeAgo
    };

});