/* @bora:meta
{
  "id": "relatime:sse",
  "depends": ["ui:base", "engine:hooks"]
}
*/

//SE Module
var appSE = function AppSe(fl){
    var self = this;
    this.fl = (typeof fl === 'string') ? fl : 'se_m.php';
    this.ths_source = null;
    this.error = null;
    this.ssePaused = false;

    this.lastEventId = null;
    this.lastVersion = 0;

    this.factHandlers = {}; // {type: [fn,fn] }
    this.factQueue = [];
    this.processing = false;

    this.lastParams;
    this.successCallback = null;
    this.errorCallback = null;

    this.userID = null;
    this.sessionID = null;

    this.test = function(){
        alert('Test');
    };

    this._readyHandlers = [];

    this.onReady = function(fn) {
        if (self._ready) {
            fn(self);
        } else {
            self._readyHandlers.push(fn);
        }
    };

    this.on = function(type, handler) {
        // alert('SSE Tree');
        console.log(`LISTENER:: ${type}`);
        if (!self.factHandlers[type]) {
            self.factHandlers[type] = [];
            
        }
        self.factHandlers[type].push(handler);
    };

    this.off = function(type, handler) {
        if (!self.factHandlers[type]) return;
        self.factHandlers[type] =
            self.factHandlers[type].filter(h => h !== handler);
    };

    this.subscribe = function(params, successCallback, errorCallback){ 
        var evt = params['event'];

        self.lastParams = params;
        self.successCallback = successCallback;
        self.errorCallback = errorCallback;

        self.userID = params['userID'];
        self.sessionID = params['sessionID'];

        params.since = app.safeParse(
            app.getCookie('lvui_versions'),
            {}
        );
        // var versions = app.getCookie('lvui_versions')
        // params.since = JSON.parse(versions) ?? {};

        console.log('PARAMS:: ',params);

            if (typeof (EventSource) !== "undefined" && typeof (params) !== "undefined" ) {
                // var url = "https://api.ilebora.com/assets/plugins/sse/sse_p.bu?id="+id+'&userID='+usr+'&event='+event;
                // var url = rd('baseUrl')+"/assets/plugins/sse/se_m.bu?id="+id+'&lastID='+last+'&userID='+usr+'&sessionID='+ses+'&event='+event;
                var base = (typeof params.base !== 'undefined') ? params.base : rd('baseUrl');
                
                var url = base + "vendor/ilebora/core-slim-sec/public/core/realtime/js/" + self.fl + "?req=" + btoa(JSON.stringify(params));

                // console.log("SE:: "+url);
                // alert(base);


                if(self.ths_source){
                    self.closeConnecton();
                }

                // if (self.lastVersion) {
                //     params.since = params.since || {};
                //     params.since.tree_graph = self.lastVersion;
                // }

                self.ths_source= new EventSource(url);

                self.ths_source.onopen = function (event) {
                    // console.log("onopen", evt, event);
                };
                self.ths_source.onerror = function (event) {
                    // console.log("onerror", evt, event);

                    // console.error("Server-Sent Events error:", event);

                    // Check the event type for more specific information
                    if (event.eventPhase === EventSource.CLOSED) {
                        // console.error("Connection closed");
                    } else if (event.readyState === EventSource.CONNECTING) {
                        // console.error("Still reconnecting...");
                    } else {
                        // console.error("Unknown error type");
                    }
                };

                self.ths_source.onclose = function (event) {
                    // console.error("onclose", evt, event);

                };

                self.ths_source.addEventListener(evt, function (e) {
                    // console.log('PAYLOAD:: ', e.data);
                    // if (self.ssePaused) return;

                    let payload;
                    try {
                        payload = JSON.parse(e.data);
                        console.log('PAYLOAD:: ', payload);
                    } catch {
                        return;
                    }

                    // Batch support
                    if (payload.batch && Array.isArray(payload.batch)) {
                        payload.batch.forEach(queueFact);
                        return;
                    }

                    // Single fact
                    if (payload.type) {
                        self.queueFact(payload);
                    }
                });

            } else {
                //No Support
                self.error = "Sorry, your browser does not support SSE...";
            }

        //Handlers
        self._ready = true;
        self._readyHandlers.forEach(fn => fn(self));
        self._readyHandlers = [];
        
    };

    this.processQueue = function() {
        if (sseBusy) return;
        if (sseQueue.length === 0) return;

        sseBusy = true;

        requestAnimationFrame(() => {
            const data = sseQueue.shift();
            handleSSE(data);
            sseBusy = false;
            processQueue();
        });
    };

    this.changeEndpoint = function(newUrl) {
        self.closeConnecton(); // Close existing connection
        self.ths_source = new EventSource(newUrl);
        // Reassign handlers to the new EventSource instance
        // self.ths_source.onmessage = ...;
        // self.ths_source.onerror = ...;
        // self.ths_source.onopen = ...;
    };

    this.closeConnecton = function(){
        self.pause();
        if(self.ths_source){
            // alert('here close connection');
            self.ths_source.close();
        }
    };

    this.pause = function(){
        self.ssePaused = true;
    };

    this.resume = function(){
        self.ssePaused = false;
    };

    window.addEventListener('beforeunload', function() {
        console.log('Closing SSE connection');
        self.closeConnecton(); 
    });

    window.addEventListener('unload', function() {
        self.closeConnecton(); // Clean up on page unload
    });

    this.dispatchFact = function (msg) {
        if (!Array.isArray(msg.data)) return;

        msg.data.forEach(event => {
            const type = event.type;

            // 1. Global handlers (*)
            const wildcardHandlers = self.factHandlers['*'] || [];

            // 2. Type-specific handlers
            const typeHandlers = self.factHandlers[type] || [];

            const handlers = [...wildcardHandlers, ...typeHandlers];

            if (handlers.length === 0) return;

            handlers.forEach(fn => {
                try {
                    fn(event, msg); // pass event + envelope if needed
                } catch (e) {
                    console.error('SSE handler failed:', type, e);
                }
            });
        });
    };

    this.queueFact =  function(msg) {
        console.log('queueFact',msg);
        self.factQueue.push(msg);
        if (!self.processing) self.processQueue();
    };

    this.processQueue = function() {
        console.log('processQueue...');
        if (self.factQueue.length === 0) {
            self.processing = false;
            return;
        }

        self.processing = true;
        requestAnimationFrame(() => {
            console.log('dispatchFact...');
            self.dispatchFact(self.factQueue.shift());
            self.processQueue();
        });
    };

    this.updateWidgetVersions = function (lvui) {
        if (!lvui || typeof lvui !== 'object') return;

        // Load last acknowledged versions
        let versions = app.safeParse(
            localStorage.getItem('lvui_versions') || '{}'
        );

        let changed = false;

        const key = lvui.widget;
        const newVersion = lvui.version;

        if (versions[key] !== newVersion) {
                versions[key] = newVersion;
                changed = true;
        }

        // Nothing new acknowledged → do nothing
        if (!changed) return;

        // Persist locally (authoritative client-side cache)
        localStorage.setItem(
            'lvui_versions',
            JSON.stringify(versions)
        );

        // Send ACK to server (fire-and-forget)
        // fetch('api/modules/realtime/ackwrite', {
        //     method: 'POST',
        //     headers: {
        //         'Content-Type': 'application/json'
        //     },
        //     body: JSON.stringify({
        //         userID: self.userID,
        //         sessionID: self.sessionID,
        //         versions: versions
        //     })
        // }).catch(() => {
        //     // Intentionally silent:
        //     // if ACK fails, SSE will resend → correctness preserved
        // });
    };

    // this.updateWidgetVersions = function(lvui) {
    //     console.log('UPDATE Widget',lvui);
    //     let versions = app.getCookie('lvui_versions') || '{}';
    //         versions = app.safeParse(versions);
    //     console.log('VERSIONS:: ',versions);

    //     Object.keys(lvui).forEach(name => {
    //         versions[name.toLowerCase()] = lvui[name].version;
    //     });

    //     document.cookie = 'lvui_versions=' + JSON.stringify(versions);
        
    //     localStorage.setItem('local',versions);
        
    //     // document.cookie = 'lvui_versions=' +
    //     //     btoa(JSON.stringify(versions));//'; path=/';
    //     // self.pause();
    //     // self.closeConnecton();
    //     // self.subscribe(self.lastParams, self.successCallback, self.errorCallback);
    //     var local = localStorage.getItem('lvui_versions')
    //     if(versions != local){
    //         fetch('api/modules/realtime/ackwrite', {
    //             method: 'POST',
    //             body: JSON.stringify({
    //                 userID:self.userID,
    //                 sessionID:self.sessionID,
    //                 versions: versions
    //             })
    //         });
    //     }
            
    // };
    
};






// function handleFact(msg) {
//     switch (msg.type) {

//         case 'tree.node.updated':
//             familyTree.updateNode(msg.data.id, msg.data);
//             break;

//         case 'tree.graph.invalidated':
//             familyTree.reloadTree();
//             break;

//         case 'lvui.updated':
//             self.lvuiUpdator(msg);
//             break;

//         default:
//             console.debug('Unhandled fact:', msg.type, msg);
//     }

//     if (msg.meta && msg.meta.v) {
//         self.lastVersion = msg.meta.v;
//     }
// }

function handleLegacy(resp) {
    // This is basically your old logic
    var evt = self.currentEvent; // store params.event here if needed
    var data = resp && resp[evt];

    if (!data) return;

    if (data.response === "success") {
        if (typeof successCallback === 'function') {
            successCallback(data);
        }
    } else {
        if (typeof errorCallback === 'function') {
            errorCallback(data);
        }
    }
}

// Realtime module JS
app.SSE = new appSE('se_m.bu');

// 🔑 announce capability
app.provide('sse', app.SSE);



FactBus.on('lvui.updated', function (event) {
    console.log('Fact:: lvui.updated');
    // ACK versions (leader or not — idempotent)
    app.SSE.updateWidgetVersions(event);

    // Apply UI updates
    liveUiUpdates(event, false);
});

FactBus.on('lvui.updatetr', function (event) {
    console.log('Fact:: lvui.updatedtr');
    app.SSE.updateWidgetVersions(event);
    liveUpdateTable(
        event.table,
        event.items,
        event.funct
    );

    liveUpdatePitm(
        event.items,
        event.funct
    );
});