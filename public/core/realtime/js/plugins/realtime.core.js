__BORA_REGISTER_PLUGIN__(
'realtime.core',
async function(scope){

    const leader = await scope.getService('realtime.leader');
    const sse    = await scope.getService('realtime.sse');


    const state = {
        mounted: false
    };

    function mount(){
        if (state.mounted) return;
        state.mounted = true;

        leader.start();

        // 🔥 CRITICAL: bind leader → SSE lifecycle
        scope.on('realtime:leader-change', handleLeaderChange);

        // 🔥 initial boot
        if (leader.isLeader()) {
            startSSE();
        }

        scope.on('realtime.events', handleRealtimeEvents);

        console.log('[Realtime] mounted');
    }

    function unmount(){
        if (!state.mounted) return;
        state.mounted = false;

        leader.stop();
        sse.closeConnection();

        console.log('[Realtime] unmounted');
    }

    function handleLeaderChange({ isLeader }){
        if (isLeader) {
            startSSE();
        } else {
            sse.closeConnection();
        }
    }

    function startSSE(){

        // prevent duplicate connections
        sse.closeConnection();

        // ⚠️ YOU MUST PROVIDE PARAMS (this was in Twig before)
        sse.subscribe({
            id: scope.config?.id || '',
            userID: rd('uID') || '0',
            sessionID: rd('sessID'),
            event: scope.config?.event || 'updatesmain',
            timer: scope.config?.timer || 20,
            base: scope.config?.baseURL || rd('baseUrl'),
            leaderEpoch: leader.getEpoch()
        });

        console.log('[Realtime] SSE started (leader)');

        // alert(rd('uID')||rd('bID'));
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

    return { mount, unmount };

},
{

    requires:['realtime.leader'],//,'hooks','events'],
    // activateOn:(route)=> route.startsWith('portal') || route.startsWith('bo')
    //TODO:: runtime face mount
    // faces: ['client', 'admin']
});