__BORA_REGISTER_SERVICE__('realtime.sse', async function(scope){

    const hooks = await scope.getService('hooks');
    const appCore = await scope.getPlugin('app.core');

    // Create SSE connection
    const instance = createSSE();

    // Register with AppCore
    appCore?.setSSE?.(instance);

    bindNavigationLifecycle();

    // scope.on('runtime:started', bindNavigationLifecycle);
    
    let offBefore, offAfter, offError;
    function bindNavigationLifecycle(){

        // offBefore = 
        scope.on('page.beforeLoad', () => {
            instance?.pause?.();
        });

        let resumeTimer = null;

        // offAfter = 
        scope.on('page.afterLoad', ({ url, response }) => {
            clearTimeout(resumeTimer);
            resumeTimer = setTimeout(() => {
                instance?.resume?.();
            }, 50);
        });

        // offError = 
        scope.on('page.loadError', ({ url, error }) => {
            instance?.resume?.();
        });

        // tab visibility stays as-is (DOM event, not runtime event)
        document.addEventListener('visibilitychange', handleVisibility);
    }

    function handleVisibility(){
        if (document.hidden) {
            // instance.pause();
        } else {
            // instance.resume();
            // alertBora.alert('visible again');
            console.log('[UI] tab visible again');
        }
    }

    function unbindNavigationLifecycle(){
        // offBefore?.();
        // offAfter?.();
        // offError?.();
        document.removeEventListener('visibilitychange', handleVisibility);
    }

    const appCompat = {
        safeParse: (str, fallback) => {
            try { return JSON.parse(str); }
            catch { return fallback; }
        },
        getCookie: (name) => {
            const match = document.cookie.match(
                new RegExp('(^| )' + name + '=([^;]+)')
            );
            return match ? match[2] : null;
        }
    };

    // 🔥 TEMPORARY BRIDGE
    window.appUtils = appCompat;

    function AppSe(fl){
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
            console.log(`LISTENER N1:: ${type}`);
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

            params.since = appUtils.safeParse(
                appUtils.getCookie('lvui_versions'),
                {}
            );
            // var versions = appUtils.getCookie('lvui_versions')
            // params.since = JSON.parse(versions) ?? {};

            console.log('PARAMS N:: ',params);

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
                            console.log('PAYLOAD N:: ', payload);
                            console.log('PAYLOAD TYPE:: ', payload.data.events);
                        } catch {
                            return;
                        }

                        // Batch support
                        if (payload.data.events && Array.isArray(payload.data.events)) {
                            payload.data.events.forEach(self.queueFact);
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
            if(self.ths_source){
                self.ths_source.close();
                self.ths_source = null;
            }
            self.ssePaused = true;
        };


        this.resume = function(){
            if(!self.ssePaused) return;

            self.ssePaused = false;
            if(self.lastParams){
                self.subscribe(
                    self.lastParams,
                    self.successCallback,
                    self.errorCallback
                );
            }

        };

        window.addEventListener('beforeunload', function() {
            console.log('Closing SSE connection N');
            self.closeConnecton(); 
        });

        //  window.addEventListener('pagehide', function () {
        //     self.closeConnection();
        // });

        this.dispatchFact = function (msg) {
            console.log('dispatchFact to realtime:' + msg.channel, msg);

            scope.emit(
                'realtime:' + msg.channel, 
                msg
            );
        };

        this.queueFact =  function(msg) {
            console.log('queueFact N'+msg.id, msg);
            self.factQueue.push(msg);
                if (!self.processing) self.processQueue();
            };

        this.processQueue = function() {
            console.log('processQueue N...');
            if (self.factQueue.length === 0) {
                self.processing = false;
                return;
            }

            self.processing = true;
            requestAnimationFrame(() => {
                console.log('dispatchFact N...');
                self.dispatchFact(self.factQueue.shift());
                self.processQueue();
            });
        };

        this.updateWidgetVersions = function (lvui) {
            if (!lvui || typeof lvui !== 'object') return;

            // Load last acknowledged versions
            let versions = appUtils.safeParse(
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

        };
    }

    function createSSE(){
        return new AppSe('se_m.bu');
    }

    return {
        on: (...args) => instance?.on?.(...args),
        off: (...args) => instance?.off?.(...args),
        subscribe: (...args) => instance?.subscribe?.(...args),
        pause: () => instance?.pause?.(),
        resume: () => instance?.resume?.(),
        updateWidgetVersions: (lvui) => instance?.updateWidgetVersions?.(lvui),
        closeConnection: () => instance?.closeConnecton?.(),
        _raw: instance,
        unbindNavigationLifecycle
    };

});