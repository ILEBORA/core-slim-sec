__BORA_REGISTER_PLUGIN__(
'activity.stories.viewer',

async function(scope){

    const uiActions =
        await scope.getService('ui.actions');

    const state = {
        stories: [],
        index: 0,
        timer: null,
        duration: 5000
    };

    init();

    function init(){

        uiActions.register(
            'story.next',
            next
        );

        uiActions.register(
            'story.prev',
            prev
        );

        // mount();

    }

    function mount(actorId){
        // alert(actorId);
        if(!actorId) return;

        load(actorId);
        
    }

    function load(actorId){

        $.getJSON(
            `api/modules/activity/stories/preview/${actorId}`
        ).done(resp => {

            if(!resp.success) return;

            state.stories = resp.data;

            state.index = 0;

            render();

        });

    }

    function render(){

        const story =
            state.stories[state.index];

        if(!story) return;

        const $viewer = $('.story-viewer').last();
        state.$viewer = $viewer;
        // alert($viewer.length);
        state.$viewer
            .find('.story-avatar')
            .attr(
                'src',
                story.actor?.avatar_url || ''
            );
        // $('.story-avatar')
        //     .attr(
        //         'src',
        //         story.actor?.avatar_url || ''
        //     );

        $('.story-username')
            .text(
                story.actor?.username || ''
            );

        $('.story-image')
            .attr(
                'src',
                story.payload?.full || ''
            );

        $('.story-text')
            .text(
                story.body || ''
            );

        buildProgress();

        startTimer();

    }

    function buildProgress(){

        const html = state.stories
            .map((s,i)=>`
                <div class="story-progress">
                    <div
                        class="story-progress-bar
                        ${i < state.index ? 'filled' : ''}"
                    ></div>
                </div>
            `)
            .join('');

        $('.story-progress-wrap')
            .html(html);

    }

    function startTimer(){

        clearTimeout(state.timer);

        const $bar = $('.story-progress-bar')
            .eq(state.index);

        $bar.css({
            width:'0%'
        });

        setTimeout(()=>{

            $bar.css({
                transition:
                    `width ${state.duration}ms linear`,
                width:'100%'
            });

        },50);

        state.timer = setTimeout(()=>{
            next();
        }, state.duration);

    }

    function next(){

        if(
            state.index >=
            state.stories.length - 1
        ){
            close();
            return;
        }

        state.index++;

        render();

    }

    function prev(){

        if(state.index <= 0){
            return;
        }

        state.index--;

        render();

    }

    function close(){

        clearTimeout(state.timer);

        __BORA_APP__?.emit('esc');

    }

    return {
        mount
    };

});