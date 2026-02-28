__BORA_REGISTER_PLUGIN__('ActivityStories', function(scope){

    const sse = scope.getService('realtime.sse');

    function mount(){

        if(!sse) return;

        sse.on('stories', handleStoriesEvent);
    }

    function unmount(){
        sse?.off?.('stories', handleStoriesEvent);
    }

    function handleStoriesEvent(msg){
        loadStories();
    }

    return { mount, unmount };

}, {
    requires: ['realtime.sse']
});