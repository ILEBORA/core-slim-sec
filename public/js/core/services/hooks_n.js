__BORA_REGISTER_SERVICE__('hooks', function(scope){

    class BoraHooks {

        constructor() {
            this.hooks = new Map();
        }

        /* =========================
           REGISTRATION
        ========================= */

        add(name, callback, options = {}) {

            if (!name || typeof callback !== 'function') {
                return;
            }
        
            /*
            |--------------------------------------------------------------------------
            | Normalize options
            |--------------------------------------------------------------------------
            */
        
            const key =
                typeof options === 'string'
                    ? options
                    : options.key || null;
        
            const replace =
                typeof options === 'object'
                    ? options.replace === true
                    : false;
        
            /*
            |--------------------------------------------------------------------------
            | Initialize hook collection
            |--------------------------------------------------------------------------
            */
        
            if (!this.hooks[name]) {
                this.hooks[name] = [];
            }
        
            /*
            |--------------------------------------------------------------------------
            | Anonymous listeners
            |
            | No key = always allowed.
            |--------------------------------------------------------------------------
            */
        
            if (!key) {
        
                this.hooks[name].push({
                    key: null,
                    callback
                });
        
                return;
            }
        
            /*
            |--------------------------------------------------------------------------
            | Find existing keyed listener
            |--------------------------------------------------------------------------
            */
        
            const index =
                this.hooks[name].findIndex(
                    listener => listener.key === key
                );
        
            /*
            |--------------------------------------------------------------------------
            | No existing listener
            |--------------------------------------------------------------------------
            */
        
            if (index === -1) {
        
                this.hooks[name].push({
                    key,
                    callback
                });
        
                return;
            }
        
            /*
            |--------------------------------------------------------------------------
            | Existing listener
            |--------------------------------------------------------------------------
            */
        
            if (!replace) {
        
                console.warn(
                    `[hooks] Listener already registered: ${name}:${key}`
                );
        
                return;
            }
        
            /*
            |--------------------------------------------------------------------------
            | Replace existing listener
            |--------------------------------------------------------------------------
            */
        
            this.hooks[name][index] = {
                key,
                callback
            };
        }
        
        addO(name, func, priority = 10) {

            if(!this.hooks.has(name)){
                this.hooks.set(name, []);
            }

            const list = this.hooks.get(name);

            list.push({ func, priority });

            // Higher priority first
            list.sort((a, b) => b.priority - a.priority);

            return this;
        }

        remove(name, func){

            if(!this.hooks.has(name)) return this;

            const filtered = this.hooks
                .get(name)
                .filter(h => h.func !== func);

            this.hooks.set(name, filtered);

            return this;
        }

        clear(name){
            this.hooks.delete(name);
            return this;
        }

        has(name){
            return this.hooks.has(name) && this.hooks.get(name).length > 0;
        }

        get(name){
            return this.hooks.get(name) || [];
        }

        mock(name, fn){
            this.hooks.set(name, [{ func: fn, priority: 1000 }]);
        }

        /* =========================
           EXECUTION
        ========================= */

        async call(name, ...params){

            if(!this.hooks.has(name)) return;

            for(const { func } of this.hooks.get(name)){

                try {
                    func(...params);
                }
                catch(error){

                    console.error(`[Hook Error: ${name}]`, error);

                    // Optional: forward to logger service
                    const logger = await scope.getService('logger');
                    if(logger && logger.error){
                        logger.error('Hook failure', { name, error });
                    }
                }
            }
        }

        async callAsync(name, ...params){

            const list = this.hooks.get(name);

            if(!list || list.length === 0){
                return [];
            }

            const results = [];

            for(const { func } of list){

                try {
                    const res = await func(...params);
                    results.push(res);
                }
                catch(error){

                    console.error(`[Async Hook Error: ${name}]`, error);

                    const logger = await scope.getService('logger');
                    if(logger && logger.error){
                        logger.error('Async hook failure', { name, error });
                    }
                }
            }

            return results;
        }

        async callAsyncUntilFalse(name, ...args){

            const list = this.hooks.get(name);

            if(!list || list.length === 0){
                return true; // no blockers → allow
            }

            for(const { func } of list){

                try{
                    const res = await func(...args);

                    if(res === false){
                        return false;
                    }
                }
                catch(error){

                    console.error(`[Async Hook Error: ${name}]`, error);

                    const logger = await scope.getService('logger');
                    if(logger && logger.error){
                        logger.error('Async hook failure', { name, error });
                    }
                }
            }

            return true;
        }

        //END fn
        
    }

    /* ==================================================
       RETURN SINGLETON INSTANCE
    ================================================== */

    return new BoraHooks();
});


// appHooks.addHook("log", console.log);
// // appHooks.call("log", "This is a log message.");
// appHooks.addHook("config:update", (key, value) => {
//     // Update application configuration
//     // Example: config[key] = value;
// });
// // appHooks.call("config:update", "theme", "dark");
// //Testing
// appHooks.addHook("test:mock", (eventName, mockFunction) => {
//     // Mock behavior for testing
//     appHooks.hooks[eventName] = [mockFunction];
// });
// appHooks.call("test:mock", "apiCall", () => console.log("Mock API call"));

// appHooks.addHook("alt", alert);
// // appHooks.call("alt", console.log); //Add Multiple
// // appHooks.call("alt", alert); //Add Multiple
// appHooks.call("alt", "this");

// // Add hooks for beforeSave and afterSave
// appHooks.addHook("beforeSave", (data) => {
//     console.log("Before saving:", data);
//     // Perform pre-save operations
// });

// appHooks.addHook("afterSave", (data) => {
//     // Perform post-save operations
//     console.log("After saving:", data);
// });

// // Simulate save operation
// var data = {test:'testing'};

// // Execute hooks before saving
// appHooks.call("beforeSave", data);

// // Save data

// // Execute hooks after saving
// appHooks.call("afterSave", data);

// //Analytics 
// appHooks.addHook("analytics", (eventName, eventData) => {
//     console.log("Analytics:", eventName, eventData);
// });
// // Trigger analytics tracking
// var eventData = {test:'testing'};
// appHooks.call("analytics", "UserAction", eventData);

// appHooks.call("alt", "this");
// //End Hooks

// //More testing
// appHooks.addHook("authenticate", (user) => {
//     // Check user authentication
//     if (!user.authenticated) {
//         throw new Error("User not authenticated");
//     }
// });

// appHooks.addHook("authorize", (user, resource) => {
//     // Check user authorization for resource access
//     if (!user.permissions.includes(resource)) {
//         throw new Error("User not authorized for resource access");
//     }
// });

// const user = { authenticated: true, permissions: ["read", "write"] };
// const resource = "write";

// appHooks.call("authenticate", user);
// appHooks.call("authorize", user, resource);


// // Real-time Updates with WebSockets
// appHooks.addHook("realtimeUpdate", (data) => {
//     // Send real-time updates to clients via WebSockets
//     console.log("Real-time update:", data);
// });

// const newData = { /* new data */ };
// appHooks.call("realtimeUpdate", newData);


// // Error Handling and Monitoring
// appHooks.addHook("error", (error) => {
//     // Log errors and send error reports to monitoring service
//     console.error("Error occurred:", error);
//     // Send error report to monitoring service
//     // MonitoringService.sendErrorReport(error);
// });

// try {
//     // Code that might throw an error
//     throw new Error("Something went wrong");
// } catch (error) {
//     appHooks.call("error", error);
// }


// // Custom Business Logic
// appHooks.addHook("beforeCheckout", (cart) => {
//     // Apply custom pricing rules before checkout
//     console.log("Applying custom pricing rules...");
//     // Modify cart object with custom prices
// });

// appHooks.addHook("afterCheckout", (order) => {
//     // Perform additional processing after checkout
//     console.log("Order processed successfully:", order);
// });

// const cart = { /* shopping cart data */ };
// const order = { /* order data */ };

// appHooks.call("beforeCheckout", cart);
// // Checkout process
// appHooks.call("afterCheckout", order);

