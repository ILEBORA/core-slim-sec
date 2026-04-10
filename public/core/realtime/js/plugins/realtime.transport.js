__BORA_REGISTER_PLUGIN__(
'realtime.transport',
async function(scope){

    const sse = await scope.getService('realtime.sse');
    const leader = await scope.getService('realtime.leader');

    const state = {
        mounted: false
    };

    function mount(){
        if (state.mounted) return;
        state.mounted = true;
        // alert('sse transport');
        sse.on('*', function(envelope){
            const event = envelope.type;

            console.log('SSE TRANSPORT::', event, envelope);

            scope.emit(event, envelope);

            if(leader.isLeader()){
                authNotify('fact', rd('bID'), event);
            }

        });

    }

    function unmount(){
        if (!state.mounted) return;
        state.mounted = false;  
        sse.off('*'); // Unbind all events
    }   

    return { mount, unmount };

},
{
    requires:['realtime.sse','realtime.leader'],
    // activateOn:(route)=>route.startsWith('portal')
    // faces: ['client', 'admin']
});