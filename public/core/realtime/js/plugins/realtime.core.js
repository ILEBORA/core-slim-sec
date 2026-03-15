__BORA_REGISTER_PLUGIN__(
'RealtimeCore',
function(scope){

    const leader = scope.getService('realtime.leader');
    const hooks  = scope.getService('hooks');
    const events = scope.getService('events');

    let mounted = false;

    function mount(){

        if(mounted) return;
        mounted = true;

        leader.start();

        scope.on('realtime.events', handleRealtimeEvents);

        console.log('[Realtime] mounted');
    }

    function unmount(){

        if(!mounted) return;
        mounted = false;

        leader.stop();

        console.log('[Realtime] unmounted');
    }

    function handleRealtimeEvents(event){
        console.log('handleRealtimeEvents', event);
        const list = event?.data?.events || [];
        console.log('handleRealtimeEvents List', list);
        list.forEach(e => {

            if(!e.channel) return;

            console.log('EMIT:: realtime:' + e.channel,e);
            scope.emit(
                'realtime:' + e.channel, 
                e
            );

        });

    }

    function handleRealtimeEventsO(event){

        const list = event?.data?.events || [];

        list.forEach(e => {

            if(!e.channel || !e.payload) return;

            scope.emit(
                'realtime:' + e.channel,
                e.payload
            );

        });
    }

    return { mount, unmount };

},
{
    requires:['realtime.leader','hooks','events'],
    activateOn:(route)=> route.startsWith('portal')
});