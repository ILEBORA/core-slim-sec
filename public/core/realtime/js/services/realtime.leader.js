__BORA_REGISTER_SERVICE__('realtime.leader', function(scope){

    const LOCK_KEY = 'sse-leader-lock';
    const HEARTBEAT_MS = 2000;
    const STALE_MS = 6000;
    const CHANNEL_NAME = 'sse-leader-election';
    const uuid = (
        crypto?.randomUUID?.() ||
        ([1e7]+-1e3+-4e3+-8e3+-1e11)
            .replace(/[018]/g, c =>
                (
                    c ^
                    crypto.getRandomValues(
                        new Uint8Array(1)
                    )[0] &
                    15 >>
                    c / 4
                ).toString(16)
            )
    );
    const TAB_ID = sessionStorage.getItem('TAB_ID') || (() => {
        const id = (
                    crypto?.randomUUID?.() ||
                    ([1e7]+-1e3+-4e3+-8e3+-1e11)
                        .replace(/[018]/g, c =>
                            (
                                c ^
                                crypto.getRandomValues(
                                    new Uint8Array(1)
                                )[0] &
                                15 >>
                                c / 4
                            ).toString(16)
                        )
                );
        sessionStorage.setItem('TAB_ID', id);
        return id;
    })();

    let isLeader = false;
    let currentEpoch = 0;
    let interval = null;

    const leaderChannel = new BroadcastChannel(CHANNEL_NAME);

    const now = () => Date.now();

    function readLock(){
        try {
            return JSON.parse(localStorage.getItem(LOCK_KEY) || '{}');
        } catch {
            return {};
        }
    }

    function writeLock(lock){
        localStorage.setItem(LOCK_KEY, JSON.stringify(lock));
    }

    function tryBecomeLeader(){
        const lock = readLock();
        const t = now();
        const stale = !lock.tabId || (t - lock.ts) > STALE_MS;

        if(stale){
            const nextEpoch = (lock.epoch || 0) + 1;

            const claim = {
                tabId: TAB_ID,
                epoch: nextEpoch,
                ts: t
            };

            writeLock(claim);

            leaderChannel.postMessage({
                type:'leader-claim',
                claim
            });

            currentEpoch = nextEpoch;
            return true;
        }

        if(lock.tabId === TAB_ID){
            currentEpoch = lock.epoch || currentEpoch;
            return true;
        }

        return false;
    }

    function resignLeadership(){

        const lock = readLock();
    
        if(lock.tabId === TAB_ID){
    
            localStorage.removeItem(LOCK_KEY);
    
            leaderChannel.postMessage({
                type:'leader-resigned',
                tabId:TAB_ID
            });
    
        }
    
    }

    // document.addEventListener('visibilitychange', () => {

    //     if (document.hidden && isLeader) {
    
    //         resignLeadership();
    
    //         // pauseSSE();

    //         scope.emit('realtime:leader-pause', {
    //             isLeader,
    //             tabId: TAB_ID,
    //             epoch: currentEpoch
    //         });
    
    //     } else {
    
    //         tryBecomeLeader();
    
    //     }
    
    // });

    leaderChannel.onmessage = (e)=>{
        const msg = e.data;
        if(!msg || msg.type !== 'leader-claim') return;

        const { tabId, epoch } = msg.claim || {};
        if(!epoch) return;

        if(epoch > currentEpoch){
            currentEpoch = epoch;
            isLeader = (tabId === TAB_ID);
        }
    };

    function start(){

        if(interval) return;

        let lastLeaderState = null;

        interval = setInterval(()=>{

            const becameLeader = tryBecomeLeader();

            if(becameLeader !== lastLeaderState){
                isLeader = becameLeader;
                scope.emit('realtime:leader-change', {
                    isLeader,
                    tabId: TAB_ID,
                    epoch: currentEpoch
                });
                lastLeaderState = becameLeader;
            }

            if(isLeader){
                const lock = readLock();
                if(lock.tabId === TAB_ID){
                    lock.ts = now();
                    writeLock(lock);
                }
            }

        }, HEARTBEAT_MS);
    }

    function stop(){
        if(interval){
            clearInterval(interval);
            interval = null;
        }
    }

    return {
        start,
        stop,
        isLeader:()=>isLeader,
        getEpoch:()=>currentEpoch,
        getTabId:()=>TAB_ID
    };

});