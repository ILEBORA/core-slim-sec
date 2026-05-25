__BORA_REGISTER_PLUGIN__(
'activity.stories.viewer',

async function(scope){

    const uiActions =
        await scope.getService('ui.actions');

    const state = {

        stories: [],
        index: 0,

        timer: null,

        duration: 5000,

        paused: false,

        startedAt: null,

        remaining: 5000,

        progress: 0,

        actorId: null,

        $viewer: null
    };

    init();

    /* ==================================================
       INIT
    ================================================== */

    function init(){

        uiActions.register(
            'story.next',
            next
        );

        uiActions.register(
            'story.prev',
            prev
        );

    }

    /* ==================================================
       MOUNT
    ================================================== */

    function mount(actorId){

        if(!actorId) return;

        state.actorId = actorId;

        const $viewer =
            $('.story-viewer').last();

        if(!$viewer.length) return;

        state.$viewer = $viewer;

        bind();

        load(actorId);

    }

    /* ==================================================
       LOAD
    ================================================== */

    function load(actorId){

        $.getJSON(
            `api/modules/activity/stories/preview/${actorId}`
        ).done(resp => {

            if(!resp.success) return;

            state.stories = resp.data || [];

            state.index = 0;

            render();

        });

    }

    /* ==================================================
       RENDER
    ================================================== */

    function render(){

        const story =
            state.stories[state.index];

        if(!story) return;

        const $viewer =
            state.$viewer;

        /*
        | Avatar
        */

        $viewer
            .find('.story-avatar')
            .attr(
                'src',
                story.actor.avatar_url
            );

        /*
        | Username
        */

        $viewer
            .find('.story-username')
            .text(
                story.actor.username
            );

        /*
        | Time
        */

        $viewer
            .find('.story-time')
            .text(
                timeAgo(
                    story.created_at
                )
            );

        /*
        | Text
        */

        $viewer
            .find('.story-text')
            .text(
                story.body || ''
            );

        /*
        | Reset
        */

        state.progress = 0;

        /*
        | Media lifecycle controls timer
        */

        renderMedia(story);

    }

    function renderO(){

        const story =
            state.stories[state.index];

        if(!story) return;

        const $viewer =
            state.$viewer;

        /*
        | Avatar
        */

        $viewer
            .find('.story-avatar')
            .attr(
                'src',
                story.actor?.avatar_url || ''
            );

        /*
        | Username
        */

        $viewer
            .find('.story-username')
            .text(
                story.actor?.username || ''
            );

        /*
        | Time
        */

        $viewer
            .find('.story-time')
            .text(
                timeAgo(
                    story.created_at
                )
            );

        /*
        | Text
        */

        $viewer
            .find('.story-text')
            .text(
                story.body || ''
            );

        /*
        | Media
        */

        renderMedia(story);

        /*
        | Progress
        */

        state.progress = 0;

        buildProgress();

        // startTimer();

    }

    /* ==================================================
       MEDIA
    ================================================== */

    function renderMedia(story){

        const payload =
            story.payload || {};

        const type =
            payload.type || '';

        const full =
            payload.full || '';

        const $viewer =
            state.$viewer;

        const $image =
            $viewer.find('.story-image');

        const $video =
            $viewer.find('.story-video');

        /*
        | Image
        */
        if(
            type.includes('jpg')
            || type.includes('jpeg')
            || type.includes('png')
            || type.includes('webp')
            || type.includes('gif')
        ){

            /*
            | Reset duration
            */

            state.duration = 5000;

            state.remaining =
                state.duration;

            $video.hide();

            $image
                .attr('src', full)
                .show();

            buildProgress();

            startTimer();

            return;
        }
        // if(
        //     type.includes('jpg')
        //     || type.includes('jpeg')
        //     || type.includes('png')
        //     || type.includes('webp')
        //     || type.includes('gif')
        // ){

        //     $video.hide();

        //     $image
        //         .attr('src', full)
        //         .show();

        //     return;
        // }

        /*
        | Video
        */

        if(
            type.includes('mp4')
            || type.includes('webm')
            || type.includes('mov')
        ){
            
            $image.hide();

            $video
                .attr('src', full)
                .show();

            const video =
                $video.get(0);

            if(video){

                /*
                | Reset
                */

                video.pause();

                video.currentTime = 0;

                /*
                | IMPORTANT
                | Viewer videos should have audio
                */

                video.muted = false;

                /*
                | Wait metadata
                */

                video.onloadedmetadata = ()=>{

                    /*
                    | Use actual duration
                    */

                    state.duration =
                        Math.max(
                            1000,
                            video.duration * 1000
                        );

                    state.remaining =
                        state.duration;

                    buildProgress();

                    startTimer();

                    video.play()
                        .catch(()=>{});

                };

                /*
                | Auto-next on ended
                */

                video.onended = ()=>{

                    next();

                };

            }

            return;
        }

        // if(
        //     type.includes('mp4')
        //     || type.includes('webm')
        //     || type.includes('mov')
        // ){

        //     $image.hide();

        //     $video
        //         .attr('src', full)
        //         .show();

        //     const video =
        //         $video.get(0);

        //     if(video){

        //         video.currentTime = 0;

        //         video.play().catch(()=>{});

        //     }

        // }

    }

    /* ==================================================
       PROGRESS
    ================================================== */

    function buildProgress(){

        const html =
            state.stories
            .map((s,i)=>`

                <div class="story-progress">

                    <div
                        class="
                            story-progress-bar

                            ${i < state.index
                                ? 'filled'
                                : ''
                            }
                        "
                    ></div>

                </div>

            `)
            .join('');

        state.$viewer
            .find('.story-progress-wrap')
            .html(html);

        /*
        | Fill previous
        */

        state.$viewer
            .find('.story-progress-bar.filled')
            .css({
                width:'100%'
            });

    }

    /* ==================================================
       TIMER
    ================================================== */

    function startTimer(){

        clearTimeout(state.timer);

        state.paused = false;

        state.remaining =
            state.duration;

        state.startedAt =
            Date.now();

        animateProgress(
            state.remaining
        );

        state.timer = setTimeout(()=>{

            next();

        }, state.remaining);

    }

    function animateProgress(duration){

        const $bar =
            state.$viewer
            .find('.story-progress-bar')
            .eq(state.index);

        $bar.css({
            transition:'none',
            width:`${state.progress}%`
        });

        requestAnimationFrame(()=>{

            requestAnimationFrame(()=>{

                $bar.css({
                    transition:
                        `width ${duration}ms linear`,
                    width:'100%'
                });

            });

        });

    }

    /* ==================================================
       PAUSE / RESUME
    ================================================== */

    function pause(){

        if(state.paused) return;

        state.paused = true;

        clearTimeout(state.timer);

        state.$viewer
            .addClass('paused');

        const elapsed =
            Date.now()
            - state.startedAt;

        state.remaining -= elapsed;

        /*
        | Freeze bar
        */

        const $bar =
            state.$viewer
            .find('.story-progress-bar')
            .eq(state.index);

        const width =
            parseFloat(
                $bar.width()
            );

        const parent =
            parseFloat(
                $bar.parent().width()
            );

        state.progress =
            (width / parent) * 100;

        $bar.css({
            transition:'none',
            width:`${state.progress}%`
        });

        /*
        | Pause video
        */

        const video =
            state.$viewer
            .find('.story-video')
            .get(0);

        if(video){

            video.pause();

        }

    }

    function resume(){

        if(!state.paused) return;

        state.paused = false;

        state.$viewer
            .removeClass('paused');

        state.startedAt =
            Date.now();

        animateProgress(
            state.remaining
        );

        state.timer = setTimeout(()=>{

            next();

        }, state.remaining);

        /*
        | Resume video
        */

        const video =
            state.$viewer
            .find('.story-video')
            .get(0);

        if(video){

            video.play()
                .catch(()=>{});

        }

    }

    /* ==================================================
       NAVIGATION
    ================================================== */

    function next(){

        if(
            state.index >=
            state.stories.length - 1
        ){

            close();

            return;
        }

        clearState();

        state.index++;

        render();

    }

    function prev(){

        if(state.index <= 0){

            return;
        }

        clearState();

        state.index--;

        render();

    }

    /* ==================================================
       EVENTS
    ================================================== */

    function bind(){

        const $viewer =
            state.$viewer;

        $viewer.off('.storyViewer');

        /*
        | Hold to pause
        */

        $viewer.on(
            'mousedown.storyViewer touchstart.storyViewer',
            '.story-content',
            pause
        );

        $viewer.on(
            'mouseup.storyViewer touchend.storyViewer',
            '.story-content',
            resume
        );

        /*
        | Reply focus pause
        */

        $viewer.on(
            'focus.storyViewer',
            '.story-reply',
            pause
        );

        $viewer.on(
            'blur.storyViewer',
            '.story-reply',
            resume
        );

        /*
        | Send reply
        */

        $viewer.on(
            'click.storyViewer',
            '.story-send',
            handleReply
        );

    }

    /* ==================================================
       REPLY
    ================================================== */

    function handleReply(){

        const story =
            state.stories[state.index];

        if(!story) return;

        const $input =
            state.$viewer
            .find('.story-reply');

        const body =
            $input.val().trim();

        if(!body) return;

        $.post(
            `api/modules/activity/stories/${story.id}/reply`,
            {
                story_id: story.id,
                body
            }
        ).done(()=>{

            $input.val('');

        });

    }

    /* ==================================================
       HELPERS
    ================================================== */

    function clearState(){

        clearTimeout(state.timer);

        state.remaining =
            state.duration;

        state.progress = 0;

        const video =
            state.$viewer
            .find('.story-video')
            .get(0);

        if(video){

            video.pause();

            video.currentTime = 0;

        }

    }

    function close(){

        clearTimeout(state.timer);

        __BORA_APP__?.emit('esc');

    }

    function timeAgo(dateString){

        if(!dateString) return '';

        const seconds =
            Math.floor(
                (
                    new Date()
                    - new Date(dateString)
                ) / 1000
            );

        const intervals = {

            y:31536000,
            mo:2592000,
            d:86400,
            h:3600,
            m:60
        };

        for(const k in intervals){

            const v =
                Math.floor(
                    seconds / intervals[k]
                );

            if(v > 0){

                return `${v}${k}`;

            }

        }

        return 'now';

    }

    /* ==================================================
       PUBLIC
    ================================================== */

    return {
        mount,
        next,
        prev,
        pause,
        resume,
        close
    };

});