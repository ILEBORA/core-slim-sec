/* @bora:meta
{
  "id": "relatime:sse_initt",
  "depends": ["relatime:sse", "relatime:init"]
}
*/

app.when('sse', function (sse) {
    // if (!window.isSseLeader()) return;

    // sse.subscribe({
    //     event: 'facts',
    //     userID: rd('bID'),
    //     sessionID: rd('sessID'),
    //     leaderEpoch: window.getLeaderEpoch()
    // });

    // sse.on('*', function (event, envelope) {
    //     console.log('[SSE FACT RECEIVED]', msg);
    //     FactBus.dispatch(event, { source: 'sse', envelope });

    //     // Fan-out to other tabs
    //     authNotify('fact', rd('bID'), event);
    // });

    sse.on('*', function (event, envelope) {
        // 1️⃣ Dispatch locally
        FactBus.dispatch(event, {
            source: 'sse',
            envelope
        });

        // 2️⃣ Rebroadcast if leader
        if (window.isSseLeader()) {
            authNotify('fact', rd('bID'), event);
        }
    });
});

// app.when('sse', function (sse) {
//     var lvuiUpdator =  function(data, broadcast = true){
//         console.log('updateWidgetVersions Here::',data); 
//         sse.updateWidgetVersions(data);

//         // if(typeof data.lvui != 'undefined'){
//             console.log('lvuiUpdator Here2::',data); 
//             liveUiUpdates(data, broadcast);
//         // }

//         // add objects update
//         // if(typeof data.lvui.cartSync != 'undefined'){
//         //     // console.log('Cart Sync found...');
//         //     // console.log(data.data.lvui.cartSync);
//         //     if(typeof data.lvui.cartSync.data.update != 'undefined'){
//         //         liveUiUpdates(data.lvui.cartSync.data.update,true); //update and broadcast
//         //     }

//         //     if(typeof data.lvui.cartSync.data.updatetr != 'undefined'){
//         //         //update tr and broadcast
//         //         liveUpdateTable('#ordertable',data.lvui.cartSync.data.updatetr, 'processTr',true);
                
//         //         // TODO:: Fix glbal
//         //         liveUpdatePitm(data.lvui.cartSync.data.updatetr, 'processTr',true);

                
//         //     }
//         // }
//     };

//     // SSE receives facts
//     sse.on('*', function (event, envelope) {

//         // 1️⃣ Dispatch locally
//         FactBus.dispatch(event, {
//             source: 'sse',
//             envelope
//         });

//         // 2️⃣ Rebroadcast if leader
//         if (isLeader) {
//             authNotify('fact', rd('bID'), event);
//         }
//     });

//     // sse.on('*', function (msg) {
//     //     console.log('[SSE FACT RECEIVED]', msg);
//     // });


//     // sse.on('lvui.updated', function (msg) {
//     //     console.log('[SSE FACT lvui.update]', msg);
//     //     lvuiUpdator(msg);
//     // });

//     // sse.on('widget.events', msg => {
//     //     msg.data.forEach(evt => {
//     //         Hooks().dispatchEvent(evt.type, evt.data);
//     //     });
//     // });
// });

