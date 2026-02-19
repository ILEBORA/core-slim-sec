const defaultActions = {
    logout: (manager, value) => {
        // localStorage.removeItem("auth.token");
        // MemoryStore.clear();
        // manager.showMessage("You’ve been logged out.");
        // manager.redirectToLogin?.(); // if you have a login redirect helper
        app.logout();
    },
    forget: (manager, value) => {
        MemoryStore.clear();
        manager.showMessage("Memory cleared.");
    },
    reset: (manager, value) => {
        location.reload();
    },
    pardon: (manager, value) => {
        manager.showMessage("No worries, let’s continue...");
    }
};

const MemoryStore = {
    key: "__secure_store__",
    passphrase: "my-secret-passphrase", // ⚠️ keep this safe or generate per-user session
    store: {},

    load() {
        const saved = localStorage.getItem(this.key);
        if (saved) {
        const decrypted = CryptoJS.AES.decrypt(saved, this.passphrase).toString(CryptoJS.enc.Utf8);
        this.store = decrypted ? JSON.parse(decrypted) : {};
        } else {
        this.store = {};
        }
    },

    save() {
        const encrypted = CryptoJS.AES.encrypt(JSON.stringify(this.store), this.passphrase).toString();
        localStorage.setItem(this.key, encrypted);
    },

    get(path) {
        return (path) ? path.split('.').reduce((obj, part) => obj?.[part], this.store) : this.store;
    },

    set(path, value, sync = true) {
        const parts = path.split('.');
        let obj = this.store;
        for (let i = 0; i < parts.length - 1; i++) {
            obj = obj[parts[i]] = obj[parts[i]] || {};
        }
        obj[parts[parts.length - 1]] = value;
        this.save();

        if (sync) {
            this.syncToServer(path, value);
        }
    },
    /**
     * Save both a raw field and update user.<repoKey> automatically
     * @param {string} conditionKey - Full lookup key (eg: login.email)
     * @param {string} repoKey - Repo category (eg: profile, education, work)
     * @param {any} value - Value to save
     * @param {string} [elemKey] - Optional field key (eg: email, school, company)
     */
    saveMemoryField(conditionKey, repoKey, value, elemKey = null) {
        console.log(conditionKey, repoKey, value, elemKey);
        // 1. Save raw value at conditionKey
        this.set(conditionKey, value, false);

        // 2. Load or init repo
        let repo = this.get(repoKey);
        if (!repo || typeof repo !== "object") {
            repo = {};
        }

        // 3. Determine field key
        const fieldKey = elemKey || conditionKey.split('.').pop();

        // 4. Store value into repo
        repo[fieldKey] = value;

        // 5. Save back into MemoryStore
        this.set(repoKey, repo, true);

        // 6. (Optional) also maintain a flat `user.all` repo for universal lookup
        // let allRepo = this.get("user.all") || { data: {} };
        // allRepo[`${repoKey}.${fieldKey}`] = value;
        // this.set("user.all", allRepo, false);
        //TODO:: review if necessary
    },
    async syncToServer(path, value) {
        const token = localStorage.getItem("auth.token");
        if (!token) {
            console.log(`[MemoryStore] User not logged in, skipping sync for ${path}`);
            return;
        }

        try {
            const res = await fetch(`${CuriosityConfig.endpoint}/memory/set`, {
                method: 'POST',
                headers: {
                    "Authorization": `Bearer ${token}`,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ path, value })
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            console.log(`[MemoryStore] Synced ${path} to server.`);
        } catch (err) {
            console.warn('[MemoryStore] Failed to sync:', err);
        }
    },

    /**
     * Merge server memory into client MemoryStore
     * @param {Object} memory - Server-side memory object, e.g. { profile: {...}, education: {...} }
     */
    hydrateMemory(memory) {
        if (!memory || typeof memory !== 'object') return;
        console.warn("Memory", memory);
        Object.keys(memory).forEach(repoKey => {
            const repoData = memory[repoKey];

            // Ensure repo object format { data: {...} }
            let repo = this.get(`${repoKey}`) || {};

            if (repoData && typeof repoData === 'object') {
                Object.entries(repoData).forEach(([fieldKey, value]) => {
                    repo[fieldKey] = value;
                    // Update raw lookup but skip server sync
                    // this.set(`${repoKey}.${fieldKey}`, value, false);
                });
            }

            // Save back into MemoryStore without triggering sync
            this.set(`${repoKey}`, repo, false);
        });

    },
    clear(path = null) {
        return new Promise((resolve) => {
            if (!path) {
                // Clear everything
                this.store = {};
                console.warn('Deleting ALL from', this.key);
                localStorage.removeItem(this.key);
                resolve(); // done
                return;
            }

            console.warn('Deleting', path);
            const parts = path.split('.');
            let obj = this.store;

            for (let i = 0; i < parts.length - 1; i++) {
                if (!obj[parts[i]]) {
                    resolve(); // nothing to clear
                    return;
                }
                obj = obj[parts[i]];
            }

            // Delete the key if it exists
            if (obj && obj.hasOwnProperty(parts[parts.length - 1])) {
                delete obj[parts[parts.length - 1]];
                this.save();
            }

            console.log('After clear', this.store);
            console.log('From localStorage', localStorage.getItem(this.key));

            resolve(); // done
        });
    }
};

class WebConversationManager {
    constructor() {
        this.queue = [];
        this.active = null;
        this.output = $('#chat-container .ai-bubble');
        this.input = $('#user-input');
        this.lnk = '';
        this.persist = false;
    }

    loadCuriosities(curiosityList) {
        // if(curiosityList.length){
        //     MemoryStore.set("curiosity.level.escalate",0,false);
        // }else{
        //     MemoryStore.set("curiosity.level.escalate",1,false);
        // }
        
        this.queue.push(...curiosityList);
        this.next();
    }

    next() {
        // Keep looping until we find a question we actually need
        while (this.queue.length > 0) {
            this.active = this.queue.shift();

            if (!this.active) continue;

            MemoryStore.set("curiosity.level", this.active.level, false);
            // alert(this.active.level);

            // resolve profile from MemoryStore
            let repo = this.active.repoKey;         // e.g. "profile"
            let key  = this.active.elem_key;        // e.g. "name"
            let store = MemoryStore.get(`${repo}`);

            // handle wrapper {data, version}
            let data = store || store || {};

            // if value already exists, skip this question
            if (data[key]) {
                //TODO:: needs verification
                console.log(`✅ Skipping ${repo}.${key}, already set:`, data[key]);
                // continue; // go to next question
            }

            // otherwise ask this one
            this.showQuestion(this.active);
            this.renderInput(this.active, data[key]);
            return;
        }
        
        let escalateLevel = MemoryStore.get("curiosity.level.escalate") || 0;
        if(escalateLevel){
            this.escalateCuriosity();
            console.warn('escalation 1', this.queue.length, escalateLevel);
            alert('Here',escalateLevel);
        }else{
            MemoryStore.set("curiosity.level.escalate",0,false);
        }
        
        console.warn('escalation', this.queue.length, escalateLevel);
        // no more questions
        if(!this.checkOnce){
            setTimeout(() => this.init(), 2000);
        }
    }

    showQuestion(c) {
        this.handleInputType(c);
        var questions = c.questions;
        var cur_questionO = Array.isArray(questions) && questions.length > 0
            ? questions[Math.floor(Math.random() * questions.length)]
            : "Curious.";
        var cur_question = Array.isArray(questions) && questions.length > 0
            ? this.replacePlaceholders(questions[Math.floor(Math.random() * questions.length)])
            : "Curious.";

        this.showMessage(cur_question);
    }

    processMessage(msg){
        var msg = this.replacePlaceholders(msg);
        this.showMessage(msg);
    }

    showMessage(msg) {
        this.output.html(`
        <div class="ai-message">${msg}</div>
        `);
    }

    appendMessage(msg) {
        const div = document.createElement("div");
        div.className = "ai-message";
        div.textContent = msg; // safer than innerHTML if msg is plain text
        this.output.append(div);
    }

    replacePlaceholders(text) {
        let structuredData = MemoryStore.get() || {};
        console.log('Record', structuredData);

        let replaced = text.replace(/\{([\w.]+)\}/g, (match, path) => {
            const value = path.split('.').reduce((obj, key) => {
                return obj && obj[key] !== undefined ? obj[key] : undefined;
            }, structuredData);

            return value !== undefined ? value : ""; // empty if not found
        });

        // Auto-heal cleanup
        return replaced
            .replace(/\s{2,}/g, " ")           // collapse double spaces
            .replace(/\s+([,.!?;:])/g, "$1")   // remove space before \
            .trim()
            .replace(/([,.!?;:])\s*$/, "")     // remove trailing punctuation if dangling
            .trim();
    }

    escalateCuriosity() {
        let currentLevel = MemoryStore.get("curiosity.level") || 0;
        let escalateLevel = MemoryStore.get("curiosity.level.escalate") || 0;
        alert(escalateLevel);
        // check if all questions at this level are answered
        const itemsAtLevel = this.queue.filter(item => item.level === currentLevel);

        const allAnswered = itemsAtLevel.every(item => {
            return !!MemoryStore.get(item.conditionKey);
        });

        if (allAnswered && currentLevel > 0 && escalateLevel) {
            //Only proceed if previous list was not empty
            // currentLevel++;
            // MemoryStore.set("curiosity.level", currentLevel);
            // console.log("Curiosity escalated to level:", currentLevel);
            this.init();
        }
    }    

    handleUserInput(value) {
        //alert(value);
        if (!this.active) return;

        if(!value) return;

        // if object, convert to string before using .toLowerCase
        if (typeof value === 'object') {
            value = JSON.stringify(value); 
        }

        const lower = value.toLowerCase().trim();
        if (defaultActions[lower]) {
            defaultActions[lower](this, value);
            return; // skip normal flow
        }

        
        // Case: expected_values provided (JSON string or object)
        
        if (this.active.expected_values.length) {
            let rules = this.active.expected_values;
            
            // Parse if it’s a string from DB
            if (typeof rules === 'string') {
                try {
                    rules = JSON.parse(rules);
                } catch (e) {
                    console.error("Invalid expected_values JSON", e);
                    rules = [];
                }
            }

            if (Array.isArray(rules)) {
                for (let rule of rules) {
                    if (value === rule.value) {
                        if (rule.action) {
                            let action = rule.action;

                            // Detect if action has parentheses (i.e. function with args)
                            if (/\(.*\)/.test(action)) {
                                try {
                                    // Safely evaluate function call with arguments
                                    return (new Function("value", "curiosity", `
                                        return ${action};
                                    `))(value, curiosity);
                                } catch (e) {
                                    console.error("Failed to call action:", action, e);
                                    alert("Failed to call action: " + action);
                                    return;
                                }
                            } else {
                                // Simple function name
                                if (typeof window[action] === "function") {
                                    return window[action](value, curiosity);
                                } else {
                                    console.warn("Action not found:", action);
                                    alert("Action not found: " + action);
                                    return;
                                }
                            }
                        }

                        // Default flow if no action
                        return this.next();
                    }
                }

                // No match
                this.showErrorMessage();
                return;
            }
        }

        const valid = this.validateInput(value, this.active.validation);
        if (!valid) {
            console.log(this.active);
            this.showErrorMessage();
            return;
        }
        
        // MemoryStore.set(this.active.conditionKey, value);
        MemoryStore.saveMemoryField(
            this.active.conditionKey,
            this.active.repoKey,
            value,
            this.active.elem_key
        );
        this.input.val('');

        this.showSuccessMessage();
        // const successPrompts = this.active.successPrompts;

        // const successMessage = Array.isArray(successPrompts) && successPrompts.length > 0
        // ? this.replacePlaceholders(successPrompts[Math.floor(Math.random() * successPrompts.length)])
        // : "Noted!";

        // this.showMessage(successMessage);
        
        $('#input-container').html('');

        if (this.active.action) {
            alert(typeof this.active.action);
            if (typeof this.active.action === 'function') {
                this.active.action(value);
            } else if (typeof this.active.action === 'string' && typeof window[this.active.action] === 'function') {
                window[this.active.action](value);
            } else {
                console.warn("Invalid action type:", this.active.action);
            }
        }
        // this.escalateCuriosity();

        this.next();
    }

    validateInput(input, validation) {
        if (!validation) return true;

        switch (validation.type) {
        case "email":
            return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input);
        case "year":
            const year = parseInt(input);
            return year >= 1900 && year <= new Date().getFullYear();
        case "pin":
            return /^\d{8,12}$/.test(input);
        case "color":
            return /^#([0-9A-Fa-f]{6}|[0-9A-Fa-f]{3})$/.test(input);
        case "dropdown":
            return validation.options?.includes(input);
        default:
            return input.trim() !== "";
        }
    }
    handleInputType(curiosity) {
        console.log("Handling input type:", curiosity.inputType);

        switch (curiosity.inputType) {
            case "YEAR_PICKER":
                //this.showYearPicker(curiosity);
            break;
            case "DATE_PICKER":
                //this.showDatePicker(curiosity);
            break;
            case "COLOR_PICKER":
                //this.showColorPicker();
            break;
            case "DROPDOWN":
                //this.showDropdownPicker(this.getDropdownOptionsFor(curiosity));
            break;
            case "SYSTEM":
                // alert('TODO:: fix system loader');
                // this.showSystemLoader();
                // curiosity.action;
                let action = curiosity.action;

                // console.log('Action',curiosity);
                // if(typeof action == 'function'){
                //     alert('yes a function. call it');
                //     // window[curiosity.action]();
                //     action();
                // }else{
                //     alert('not a function');
                //     //Find a way to call the string as existing function
                // }

                if (typeof action === 'function') {
                    // Case 1: direct function reference
                    console.log('✅ Direct function, calling it');
                    action();
                } else if (typeof action === 'string') {
                    // Case 2: string path, e.g., "myFunction" or "MyNS.myFunction"
                    console.log('ℹ️ String action, resolving path');

                    let fn = action.split('.').reduce((obj, key) => {
                        return obj && obj[key] !== undefined ? obj[key] : undefined;
                    }, window);

                    if (typeof fn === 'function') {
                        console.log('✅ Found function from string, calling it');
                        fn();
                    } else {
                        console.warn(`⚠️ No function found for action: ${action}`);
                    }
                } else {
                    console.warn('⚠️ Invalid action type:', typeof action);
                }
            break;
            default:
                console.warn("Unknown input type:", curiosity.inputType);
            break;
        }
    }   

    appendUserMessage(input){
        console.log(input);
    }

    getDropdownOptionsFor(curiosity){
        return curiosity.validation.allowed;
    }

    showYearPicker(curiosity) {
        const year = prompt("Enter a year (1900 - " + new Date().getFullYear() + "):");
        if (year) {
            this.appendUserMessage(year);
            this.handleUserInput(year);
        }
    }

    showDatePicker(curiosity) {
        const date = prompt("Enter a date (e.g. YYYY-MM-DD):");
        if (date) {
            this.appendUserMessage(date);
            this.handleUserInput(date);
        }
    }

    showColorPicker() {
        const colors = ["Red", "Blue", "Green", "Yellow", "Purple", "Black", "White"];
        const color = prompt("Choose a color: " + colors.join(", "));
        if (color && colors.includes(color)) {
            this.input.val(color);
            this.handleUserInput(color);
        }
    }

    showDropdownPicker(options) {
        const prmt = prompt("Select an option: " + options.join(", "));
        if (prmt && options.includes(prmt)) {
            this.input.val(prmt);
            this.handleUserInput(prmt);
        }
    }

    showSystemLoader() {
        const email = MemoryStore.get("login.email") || "";
        const pin = MemoryStore.get("login.pin") || "";

        console.log("SYSTEM LOGIN with:", email, pin);

        // Simulate login request
        this.loginRequest(email, pin);
    }

    getQueue(){
        return this.queue;
    }

    resetCuriosities(){
        MemoryStore.clear();
        this.queue = [];
    }

    setRedirectUrl(lnk){
        this.lnk = lnk;
    }

    async loginRequest(email, pin){
        // alert('here loginRequest');
        // console.log(email, pin);
        (async()=> {
            const success = await loginUser();
                if (success) {
                    
                    console.log("Proceed inside app");
                    console.log('Success!! Welcome... token '+localStorage.getItem("auth.token"));

                    //Clear login data:
                    MemoryStore.clear();
                    //TODO:: get user memory
                    // 1) Hydrate with latest profile/memory
                    const memory = await getUserMemory();
                    if (memory.success) {
                        this.parseJwt(memory.data).then(pData => {
                            console.warn('pData', pData.data);
                            return MemoryStore.hydrateMemory(pData.data);
                        }).then(() => {
                            console.warn('showSuccessMessage');
                            this.showSuccessMessage();

                            if(typeof authChannel !== 'undefined'){
                                authChannel.postMessage({cmd:'login',usr:rd('bID'), lnk: this.lnk});
                            }

                            if(this.persist){
                                //Check curiosities
                                setTimeout(() => this.init(), 3000);
                            }else{
                                redirectTo(this.lnk);
                            }

                        }).catch(err => console.error("Decode failed", err));
                    } 

                    
                    
                } else {
                    // console.log("Stay on login page");
                    // console.log('Something went wrong... please try again');
                    // //Notify
                    // this.showErrorMessage();
                    // MemoryStore.clear();
                    // //Start again...
                    // setTimeout(() => this.init(), 3000);

                     console.log("Login failed, check why...");
        
                    const exists = await userCheckEmail(email);

                    if (!exists) {
                        // New user → start signup curiosity flow
                        console.log("Escalating to signup...");
                        await MemoryStore.clear();
                        this.queue = [];
                        MemoryStore.set("curiosity.level", 2)
                        // this.startCuriosityFlow("signup");
                    } else {
                        // Existing user but wrong pin → forgot password option
                        console.log("Wrong pin, suggest forgot password curiosity...");
                        this.queue = [];
                        MemoryStore.set("curiosity.level", 2)
                        this.showErrorMessage("Pin incorrect. Want to reset?");
                        // this.startCuriosityFlow("forgot_password");
                    }
                }
        })();
        
    }

    async signupRequest(email, pin, terms){
        alert('here signupRequest');
        console.log(email, pin, terms);
        (async()=> {
            const success = await registerUser();
                if (success) {
                    
                    console.log("Proceed inside app");
                    console.log('Success!! Welcome... token '+localStorage.getItem("auth.token"));

                    //Clear login data:
                    MemoryStore.clear();
                    //TODO:: get user memory
                    // 1) Hydrate with latest profile/memory
                    const memory = await getUserMemory();
                    if (memory.success) {
                        this.parseJwt(memory.data).then(pData => {
                            console.warn('pData', pData.data);
                            return MemoryStore.hydrateMemory(pData.data);
                        }).then(() => {
                            console.warn('showSuccessMessage');
                            this.showSuccessMessage();

                            //Check curiosities
                            setTimeout(() => this.init(), 3000);
                        }).catch(err => console.error("Decode failed", err));
                    } 

                    
                    
                } else {
                    alert('something went wrong');
                    // console.log("Stay on login page");
                    // console.log('Something went wrong... please try again');
                    // //Notify
                    // this.showErrorMessage();
                    // MemoryStore.clear();
                    // //Start again...
                    // setTimeout(() => this.init(), 3000);

                     console.log("Signup failed, check why...");
        
                    // const exists = await userCheckEmail(email);

                    // if (!exists) {
                    //     // New user → start signup curiosity flow
                    //     console.log("Escalating to signup...");
                    //     // this.startCuriosityFlow("signup");
                    //     alert('Email doesnt exist');
                    // } else {
                    //     // Existing user but wrong pin → forgot password option
                    //     console.log("Wrong pin, suggest forgot password curiosity...");
                    //     // this.queue = [];
                    //     // MemoryStore.set("curiosity.level", 2)?
                    //     this.showErrorMessage("Pin incorrect. Want to reset?");
                    //     // this.startCuriosityFlow("forgot_password");
                    //     alert('Suggest pin/password reset');
                    // }
                }
        })();
        
    }
    
    parseJwt(token) {
        return new Promise((resolve, reject) => {
            ILEBORA.use('https://cdn.jsdelivr.net/npm/jwt-decode/build/jwt-decode.min.js', function() {
                try {
                    resolve(jwt_decode(token));
                } catch (err) {
                    reject(err);
                }
            });
        });
    }

    init() {
        let currentLevel = MemoryStore.get("curiosity.level") || 0;
        fetch(`${CuriosityConfig.endpoint}/auth`, {
            method: "POST",
            headers: {
                "Authorization": "Bearer " + localStorage.getItem("auth.token"),
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                 mode: "full",
                //  level: currentLevel
                 })
        })
        .then(res => {
            if (!res.ok) {
                throw new Error(`HTTP error ${res.status}`);
            }
            return res.json();
        })
        .then(data => {
            if(data.success){
                this.parseJwt(data.data).then(pData => {
                    console.log("Data:: ",pData.data);
                    if(pData.data.length){
                        // alert('Found curiosity');
                        this.checkOnce = 0;
                        this.loadCuriosities(pData.data);
                        MemoryStore.set("curiosity.level.escalate",1,false);
                    }else{
                        // alert('blank');
                        this.checkOnce = 1;
                        MemoryStore.set("curiosity.level.escalate",0,false);
                        this.processMessage('Oops! My curiosity seems to be empty... What would you like to talk about {profile.name}.');
                    }
                }).catch(err => console.error("Decode failed", err));
            }
        })
        .catch(err => {
            console.error("Auth init failed:", err);
            // maybe redirect to login page if token invalid
        });
    }

    showErrorMessage(){
        let errorPrompts = this.active.errorPrompts;
        let errorMessage = Array.isArray(errorPrompts) && errorPrompts.length > 0
                ? errorPrompts[Math.floor(Math.random() * errorPrompts.length)]
                : "Invalid input.";
        //process message
        errorMessage = this.replacePlaceholders(errorMessage);

        this.showMessage(errorMessage);
    }

    showSuccessMessage(){
        let successPrompts = this.active.successPrompts;
        let successMessage = Array.isArray(successPrompts) && successPrompts.length > 0
                ? successPrompts[Math.floor(Math.random() * successPrompts.length)]
                : "Invalid input.";
        //process message
        successMessage = this.replacePlaceholders(successMessage);

        this.showMessage(successMessage);
    }

    redirectToLogin(){
        console.warn('redirecting you to login');
        location.reload();
    }

    renderInput(curiosityItem, text) {
        let container = $("#input-container");
        container.empty();

        if (!curiosityItem.inputHtml) {
            // SYSTEM or no-input case
            this.output.append(`<div class="system-message">Processing...</div>`);
            return;
        }

        // Append the HTML string
        container.append(curiosityItem.inputHtml);

        // Grab whatever was inserted under #user-input
        let $input = $('input#user-input ');
        let $select = $('select#user-input ');

        // if ($input.length) {
            $input.focus().select();   // focus and highlight if input exists
            setTimeout(() => {
                $input.focus();
                if(typeof text !== 'undefined'){
                    // alert('here '+ text);
                    $input.val(text);
                }
            }, 500);
            
            // alert(text);
            
        // }

        if ($select.length) {
            $select.focus();           // focus on select
        }

        // curiosity.bindInputEvents();
        
    }


    renderInputO(curiosityItem) {
        let container = $("#input-container");
        container.empty();

        let factory = curiosityInputMap[curiosityItem.inputType];
        if (!factory) {
            // fallback text input
            factory = () => $('<input>', { type: 'text', id: 'user-input' });
        }

        let field = factory(curiosityItem);
        if (field) {
            container.append(curiosityItem.inputHtml);
            
            // For an input inside #user-input
            $('#user-input input').focus();       // put cursor
            $('#user-input input').select();      // highlight text

            // For a select element
            $('#user-input select').focus();      // focus on select dropdown
            // alert(curiosityItem.inputType);
            //container.append('<button id="send-btn" class="btn">Send</button>');
            // Initialize Select2 after element is attached to DOM
            if(curiosityItem.inputType == 'DROPDOWN'){
                // alert(curiosityItem.inputType);
                
                setTimeout(() => {
                    let select = $('#user-input');
                    select.select2({
                        placeholder: "Choose an option", //config.placeholder || 
                         tags: true,
                        allowClear: true,
                        width: '100%' // make sure it stretches nicely
                    });
                },0);
            }

        } else {
            // SYSTEM type → maybe show a spinner or lock input
            this.output.append(`<div class="system-message">Processing...</div>`);
        }
    }

    // renderInputO(inputConfig) {
    //     console.log('renderInput: ',inputConfig);
    //     let field;
        
    //     switch (inputConfig.type) {
    //         case 'text':
    //         field = $('<input>', {
    //             type: 'text',
    //             id: 'user-input',
    //             placeholder: inputConfig.placeholder || 'Type here...'
    //         });
    //         break;

    //         case 'date':
    //         field = $('<input>', {
    //             type: 'date',
    //             id: 'user-input'
    //         });
    //         break;

    //         case 'select':
    //         field = $('<select>', { id: 'user-input' });
    //         inputConfig.options.forEach(opt => {
    //             field.append($('<option>', { value: opt, text: opt }));
    //         });
    //         break;

    //         case 'file':
    //         field = $('<input>', {
    //             type: 'file',
    //             id: 'user-input'
    //         });
    //         break;
    //     }

    //     $("#input-container").empty().append(field);
    //     }



    getWelcomeMessage() {
        const token = localStorage.getItem("auth.token"); // or your key
        const lastActive = parseInt(localStorage.getItem("lastActive") || "0", 10);
        const now = Date.now();
        const diffMins = (now - lastActive) / (1000 * 60);

        var $msg = '';

        if (!token) {
            if (!lastActive) {
                $msg = "Welcome! Let's get started.";
            } else if (diffMins > 60) {
                $msg = "Welcome back, guest! It's been a while.";
            } else {
                $msg = "Good to see you again!";
            }
        } else {
            if (!lastActive) {
                $msg = "Welcome, glad you logged in!";
            } else if (diffMins > 1440) { // > 1 day
                $msg = "Welcome back {profile.name}! We’ve missed you.";
            } else if (diffMins > 60) {
                $msg = "Hey, good to see you again {profile.name}!";
            } else {
                $msg = "Back so soon {profile.name}? Let's continue.";
            }
        }

        this.processMessage($msg);

        setTimeout(() => this.init(), 2000);
    }

    continueToApp(){
        console.log('continueToApp');
    }

    //Check email
    async checkEmail(email){
        // alert('here checkEmail');
        console.log(email);
        (async()=> {
            const success = await checkEmail();
                if (success) {
                    // alert('Email found... proceed with email');
                } else {
                    // alert('user not found!... Suggest signup...');
                }
        })();
        
    }
}

appHooks.addHook('user.logout.after',async function(){
    MemoryStore.clear();
});

function deleteItem(type, id){
    //Delete Item
    alert('Delete '+type+id + ' '+typeof type);
};

function editItem(type, id){
    //Delete Item
    alert('Edit '+type+id);
};