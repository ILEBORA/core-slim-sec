/* @bora:meta
{
  "id": "relatime:init",
  "depends": ["relatime:sse", "relatime:elements"]
}
*/

/**
 * =========================================================
 * Realtime Leader Election (SSE Leader)
 * =========================================================
 * Guarantees:
 *  - Single stable leader (bounded overlap only)
 *  - Fast convergence after crashes / tab close
 *  - Split-brain protection via epoch fencing
 * =========================================================
 */

/* ---------- Stable TAB ID (per tab session) ---------- */
const TAB_ID = sessionStorage.getItem('TAB_ID') || (() => {
    const id = crypto.randomUUID();
    sessionStorage.setItem('TAB_ID', id);
    return id;
})();

/* ---------- Config ---------- */
const LOCK_KEY = 'sse-leader-lock';
const HEARTBEAT_MS = 2000;   // leader heartbeat
const STALE_MS = 6000;       // leader considered dead after this
const CHANNEL_NAME = 'sse-leader-election';

/* ---------- State ---------- */
let isLeader = false;
let currentEpoch = 0;

/* ---------- Channel ---------- */
const leaderChannel = new BroadcastChannel(CHANNEL_NAME);

/* ---------- Utilities ---------- */
const now = () => Date.now();

function readLock() {
    try {
        return JSON.parse(localStorage.getItem(LOCK_KEY) || '{}');
    } catch {
        return {};
    }
}

function writeLock(lock) {
    localStorage.setItem(LOCK_KEY, JSON.stringify(lock));
}

/* ---------- Attempt Leadership ---------- */
function tryBecomeLeader() {
    const lock = readLock();
    const t = now();

    const stale = !lock.tabId || (t - lock.ts) > STALE_MS;

    if (stale) {
        const nextEpoch = (lock.epoch || 0) + 1;

        const claim = {
            tabId: TAB_ID,
            epoch: nextEpoch,
            ts: t
        };

        writeLock(claim);

        // Announce claim (epoch fencing)
        leaderChannel.postMessage({
            type: 'leader-claim',
            claim
        });

        currentEpoch = nextEpoch;
        return true;
    }

    // Already leader?
    if (lock.tabId === TAB_ID) {
        currentEpoch = lock.epoch || currentEpoch;
        return true;
    }

    return false;
}

/* ---------- Epoch Fencing (Split-Brain Resolver) ---------- */
leaderChannel.onmessage = (e) => {
    const msg = e.data;
    if (!msg || msg.type !== 'leader-claim') return;

    const { tabId, epoch } = msg.claim || {};
    if (!epoch) return;

    // Higher epoch always wins
    if (epoch > currentEpoch) {
        currentEpoch = epoch;
        isLeader = (tabId === TAB_ID);
    }
};

function notifyLeaderChange(isLeaderNow) {
    document.dispatchEvent(
        new CustomEvent('realtime:leader-change', {
            detail: {
                isLeader: isLeaderNow,
                tabId: TAB_ID,
                epoch: currentEpoch
            }
        })
    );
}

/* ---------- Heartbeat Loop ---------- */
let lastLeaderState = null;
setInterval(() => {
    const becameLeader = tryBecomeLeader();

    if (becameLeader !== lastLeaderState) {
        isLeader = becameLeader;
        notifyLeaderChange(isLeader);
        lastLeaderState = becameLeader;
    } else {
        isLeader = becameLeader;
    }

    if (isLeader) {
        const lock = readLock();
        if (lock.tabId === TAB_ID) {
            lock.ts = now();
            writeLock(lock);
        }
    }
}, HEARTBEAT_MS);
// setInterval(() => {
//     if (tryBecomeLeader()) {
//         isLeader = true;

//         // Refresh heartbeat if still leader
//         const lock = readLock();
//         if (lock.tabId === TAB_ID) {
//             lock.ts = now();
//             writeLock(lock);
//         }
//     } else {
//         isLeader = false;
//     }
// }, HEARTBEAT_MS);

/* ---------- Optional: Clean Handoff on Close ---------- */
window.addEventListener('beforeunload', () => {
    const lock = readLock();
    if (lock.tabId === TAB_ID) {
        // Mark stale immediately to speed up takeover
        lock.ts = 0;
        writeLock(lock);
    }
});

/* ---------- Public Helper ---------- */
window.isSseLeader = () => isLeader;
window.getLeaderEpoch = () => currentEpoch;
window.getTabId = () => TAB_ID;


if (window.REALTIME_DEBUG) {
    window.tryBecomeLeader = tryBecomeLeader;
}


//Realtime Poller
// let pollInterval = 1000;
// let lastEventId = 0;

// function poll() {
//     fetch(`api/modules/realtime/poll?since=${lastEventId}`)
//         .then(r => r.json())
//         .then(data => {
//             const events = data.events || [];

//             // 🔥 THIS IS THE MISSING PIECE
//             events.forEach(e => {
//                 if (!e.channel || !e.payload) return;

//                 lastEventId = Math.max(lastEventId, e.id);
//                 // Dispatch to BoraHooks
//                 console.log('[poller] dispatching', 'realtime:' + e.channel);
//                 appHooks.callHook(
//                     'realtime:' + e.channel,
//                     e.payload
//                 );
//             });

//             // Adaptive polling
//             if (events.length === 0) {
//                 pollInterval = Math.min(pollInterval + 500, 5000);
//             } else {
//                 pollInterval = 1000;
//             }

//             setTimeout(poll, pollInterval);
//         })
//         .catch(() => {
//             // Backoff on error
//             pollInterval = Math.min(pollInterval + 1000, 10000);
//             setTimeout(poll, pollInterval);
//         });
// }

// // poll();
// window.RealtimePoller = {
//     start() {
//         poll();
//     }
// };

// TODO:: move poll logic to SSE
// document.addEventListener('DOMContentLoaded', () => {
//     // Hooks should already be registered at this point
//     setTimeout(() => {
//         RealtimePoller.start();
//     }, 0);
// });


// TODO:: try SSE
// const source = new EventSource('api/modules/realtime/stream');

// source.addEventListener('message', e => {
//     const data = JSON.parse(e.data);

//     appHooks.callHook(
//         'realtime:' + data.channel,
//         data.payload
//     );
// });

// source.onerror = () => {
//     console.warn('SSE disconnected, retrying...');
// };

let lastEventId = 0;
// TODO:: move to fact bus
FactBus.on('realtime.events', function (event) {
    console.log('EVENT::',event.data.events);
    const events = event.data.events;
    events.forEach(e => {
        if (!e.channel || !e.payload) return;

        lastEventId = Math.max(lastEventId, e.id);
        // Dispatch to BoraHooks
        // console.log('ELEMENT::',e);
        console.log('[poller] dispatching', 'realtime:' + e.channel);
        appHooks.callHook(
            'realtime:' + e.channel,
            e.payload
        );
    });
    // const { channel, payload } = event;
    // if (!channel || !payload) return;

    // // 🔥 This is the SAME logic poll() used to have
    // const hook = 'realtime:' + channel;

    // console.log('[realtime-router] dispatching', hook, payload.type);

    // appHooks.callHook(hook, payload);
});