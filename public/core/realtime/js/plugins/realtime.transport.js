__BORA_REGISTER_PLUGIN__(
'RealtimeTransport',
function(scope){

    const sse = scope.getService('realtime.sse');
    const leader = scope.getService('realtime.leader');

    function mount(){
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

    return { mount };

},
{
    requires:['realtime.sse','realtime.leader'],
    activateOn:(route)=>route.startsWith('portal')
});