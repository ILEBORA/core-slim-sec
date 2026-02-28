/* @bora:meta
{
  "id": "relatime:sse_initt",
  "depends": ["relatime:sse", "relatime:init"]
}
*/

app.when('sse', function (sse) {
    // if (!window.isSseLeader()) return;
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
