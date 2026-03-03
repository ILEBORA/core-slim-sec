__BORA_REGISTER_PLUGIN__(
'RealtimeTransport',
function(scope){

    const sse = scope.getService('realtime.sse');
    const leader = scope.getService('realtime.leader');

    function mount(){

        sse.on('*', function(event, envelope){

            scope.emit('realtime.events', {
                source:'sse',
                envelope
            });

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