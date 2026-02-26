console.log('BoraPlugin');
var BoraPlugin = {
    pluginName: 'Test',
    functs: {},
    debug: false,
    events: {},

    setName(name) {
        this.pluginName = name;
    },

    registerFunc(name, func) {
        if (typeof this.functs[name] === 'undefined') {
            this.functs[name] = func.bind(this);
            this.log(`Function '${name}' registered for initialization.`, 'registerFunc');
        } else {
            this.log(`Function '${name}' already registered.`, 'registerFunc');
        }
    },

    addMethod(name, func) {
        this[name] = func.bind(this);
        this.log(`Method '${name}' added.`, 'addMethod');
    },

    addMethods(methods) {
        for (let name in methods) {
            if (methods.hasOwnProperty(name)) {
                this.addMethod(name, methods[name]);
            }
        }
    },

    removeMethod(name) {
        if (this.hasOwnProperty(name)) {
            delete this[name];
            this.log(`Method '${name}' removed.`, 'removeMethod');
        } else {
            this.log(`Method '${name}' does not exist.`, 'removeMethod');
        }
    },

    init() {
        for (let name in this.functs) {
            if (this.functs.hasOwnProperty(name)) {
                this.log(`Executing function '${name}'.`, 'init');
                this.functs[name]();
            }
        }
    },

    on(event, handler) {
        if (!this.events[event]) {
            this.events[event] = [];
        }
        this.events[event].push(handler.bind(this));
        this.log(`Event '${event}' handler registered.`, 'on');
    },

    off(event, handler) {
        if (this.events[event]) {
            this.events[event] = this.events[event].filter(h => h !== handler);
            this.log(`Event '${event}' handler deregistered.`, 'off');
        }
    },

    trigger(event, ...args) {
        if (this.events[event]) {
            this.events[event].forEach(handler => handler(...args));
            this.log(`Event '${event}' triggered.`, 'trigger');
        }
    },

    log(message, methodName) {
        if (this.debug) {
            console.log(`[${this.pluginName} - ${methodName}] :: ${message}`);
        }
    },

    setDebug(state) {
        this.debug = state;
        this.log(`Debug mode is now ${state ? 'on' : 'off'}.`, 'setDebug');
    }
};

function createPlugin(basePlugin, customConfig) {
    return Object.assign(Object.create(basePlugin), customConfig);
}

function addPlugin(pluginName, customConfig) {
    const plugin = createPlugin(BoraPlugin, customConfig);
    plugin.pluginName = pluginName;
    
    const handler = {
        //Case sensitive
        get(target, prop, receiver) {
            // console.log(`Requested property: ${prop}`);
            if (prop in target) {
                const value = Reflect.get(target, prop, receiver);
                if (typeof value === 'function') {
                    return value.bind(target); // Ensure the correct context
                }
                return value;
            } else {
                return function() {
                    console.warn(`[${customConfig.pluginName}] Function '${prop}' does not exist.`);
                };
            }
        }
    };

    // Create the proxy and ensure the correct context for logging
    const proxiedPlugin = new Proxy(plugin, handler);

    mPGs.tools[pluginName] = proxiedPlugin;

    return proxiedPlugin;
}