//Hooks
class BoraHooks {
    constructor() {
        this.hooks = {};
    }

    addHook(name, func, priority = 10) {
        if (!this.hooks[name]) this.hooks[name] = [];
        this.hooks[name].push({ func, priority });
        // Keep hooks sorted by priority (descending: 100 runs before 10)
        this.hooks[name].sort((a, b) => b.priority - a.priority);
    }

    removeHook(name, func) {
        if (this.hooks[name]) {
            this.hooks[name] = this.hooks[name].filter(hook => hook.func !== func);
        }
    }

    callHook(name, ...params) {
        const hooks = this.hooks[name];
        if (hooks) {
            for (const { func } of hooks) {
                try {
                    func(...params);
                } catch (error) {
                    console.error(`Error in ${name} hook:`, error);
                }
            }
        }
    }

    async callHookAsync(name, ...params) {
        const hooks = this.hooks[name];
        if (hooks) {
            for (const { func } of hooks) {
                try {
                    await func(...params);
                } catch (error) {
                    console.error(`Error in async ${name} hook:`, error);
                }
            }
        }
    }

    hasHook(name) {
        return !!this.hooks[name]?.length;
    }

    getHooks(name) {
        return this.hooks[name] || [];
    }

    clearHook(name) {
        delete this.hooks[name];
    }
}

const appHooks = new BoraHooks();


// appHooks.addHook("log", console.log);
// // appHooks.callHook("log", "This is a log message.");
// appHooks.addHook("config:update", (key, value) => {
//     // Update application configuration
//     // Example: config[key] = value;
// });
// // appHooks.callHook("config:update", "theme", "dark");
// //Testing
// appHooks.addHook("test:mock", (eventName, mockFunction) => {
//     // Mock behavior for testing
//     appHooks.hooks[eventName] = [mockFunction];
// });
// appHooks.callHook("test:mock", "apiCall", () => console.log("Mock API call"));

// appHooks.addHook("alt", alert);
// // appHooks.callHook("alt", console.log); //Add Multiple
// // appHooks.callHook("alt", alert); //Add Multiple
// appHooks.callHook("alt", "this");

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
// appHooks.callHook("beforeSave", data);

// // Save data

// // Execute hooks after saving
// appHooks.callHook("afterSave", data);

// //Analytics 
// appHooks.addHook("analytics", (eventName, eventData) => {
//     console.log("Analytics:", eventName, eventData);
// });
// // Trigger analytics tracking
// var eventData = {test:'testing'};
// appHooks.callHook("analytics", "UserAction", eventData);

// appHooks.callHook("alt", "this");
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

// appHooks.callHook("authenticate", user);
// appHooks.callHook("authorize", user, resource);


// // Real-time Updates with WebSockets
// appHooks.addHook("realtimeUpdate", (data) => {
//     // Send real-time updates to clients via WebSockets
//     console.log("Real-time update:", data);
// });

// const newData = { /* new data */ };
// appHooks.callHook("realtimeUpdate", newData);


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
//     appHooks.callHook("error", error);
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

// appHooks.callHook("beforeCheckout", cart);
// // Checkout process
// appHooks.callHook("afterCheckout", order);

