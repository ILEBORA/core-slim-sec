async function loginUser() {
    const email = MemoryStore.get("login.email") || "";
    const pin = MemoryStore.get("login.pin") || "";

    if (!email || !pin) {
        console.warn("Email or pin missing.");
        return false;
    }

    try {
        const res = await fetch(`${CuriosityConfig.endpoint}/auth/login`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ email, pin })
        });

        const data = await res.json();

        if (data.success && data.token) {
            console.log("Logged in", data.success);

            MemoryStore.set("auth.token", data, false);
            localStorage.setItem("auth.token", data.token);

            if(data.lnk){
                overlayLoader.show('Loading...');
                manager.setRedirectUrl(data.lnk);
            }

            return true;
        } else {
            console.warn("Login failed:", data.message || data);
            return false;
        }
    } catch (err) {
        console.error("Login error:", err);
        return false;
    }
}

async function checkEmail() {
    const email = MemoryStore.get("login.email") || "";

    if (!email) {
        console.warn("Email missing.");
        return false;
    }

    try {
        const res = await fetch(`${CuriosityConfig.endpoint}/auth/check/email`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ email })
        });

        const data = await res.json();

        if (data.success) {
            // alert('Email found.');
            manager.next();
            return true;
        } else {
            console.warn("Email not found:", data.message || data);
            // alert('Prompt signup');
            // manager.showMessage("Email not found, would you like to Signup with thos email");
            manager.showErrorMessage();
            //Update the user-input
            let container = $("#input-container");
            container.empty();

            if (!data.inputHtml) {
                alert('Input html not found.');
            }

            // Append the HTML string
            container.append(data.inputHtml);

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
            // alert('here end ');
            return false;
        }
    } catch (err) {
        console.error("Email check error:", err);
        return false;
    }
}

async function registerUser() {
    // alert('Call api register');
    const email = MemoryStore.get("signup.email") || "";
    const pin = MemoryStore.get("signup.pin") || "";
    const terms = MemoryStore.get("signup.terms") || '';

    if (!email || !pin || !terms) {
        console.warn("Email or pin or terms missing.");
        return false;
    }

    try {
        const res = await fetch(`${CuriosityConfig.endpoint}/auth/register/user`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ email, pin , terms})
        });

        const data = await res.json();

        if (data.success && data.token) {
            console.log("Signup in", data.success);

            MemoryStore.set("auth.token", data, false);
            localStorage.setItem("auth.token", data.token);

            return true;
        } else {
            console.warn("Signup failed:", data.message || data);
            return false;
        }
    } catch (err) {
        console.error("Signup error:", err);
        return false;
    }
}

/** Fetch the latest user profile/memory.
 *  Returns the payload unchanged. Caches in MemoryStore.
 */
async function getUserMemory() {
    const token = localStorage.getItem("auth.token");
    if (!token) {
        console.warn("No auth token.");
        return null;
    }

    // Try GET first; fallback to POST if your API requires it.
    const tryFetch = async (method) => fetch(`${CuriosityConfig.endpoint}/memory`, {
        method,
        headers: {
            "Authorization": "Bearer " + token,
            "Accept": "application/json",
            ...(method === "POST" ? { "Content-Type": "application/json" } : {})
        },
        ...(method === "POST" ? { body: JSON.stringify({}) } : {})
    });

    try {
        let res = await tryFetch("GET");
        if (res.status === 405 || res.status === 415) res = await tryFetch("POST"); // fallback

        if (res.status === 401) return handleUnauthorized();
        if (!res.ok) {
            console.error("getUserMemory failed:", res.status, res.statusText);
            return null;
        }

        const data = await res.json();
        // MemoryStore.set("user.memory", data, false); // cache as-is
        return data;
    } catch (err) {
        console.error("getUserMemory error:", err);
        return null;
    }
}

/** Fetch the profile curiosities (what's missing).
 *  Passes through the API payload unchanged.
 */
async function getCuriosities(mode = "full") {
    const token = localStorage.getItem("auth.token");
    if (!token) {
        console.warn("No auth token.");
        return null;
    }

    try {
        const res = await fetch(`${CuriosityConfig.endpoint}/auth`, {
            method: "POST",
            headers: {
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({ mode })
        });

        if (res.status === 401) return handleUnauthorized();
        if (!res.ok) {
            console.error("getCuriosities failed:", res.status, res.statusText);
            return null;
        }

        const data = await res.json();
        return data; // keep shape intact (e.g., { missing, curiosities, ... })
    } catch (err) {
        console.error("getCuriosities error:", err);
        return null;
    }
}


function handleUnauthorized() {
    console.warn("Unauthorized/expired token. Clearing auth and resetting.");
    localStorage.removeItem("auth.token");
    MemoryStore.set("auth.token", null);
    // Optionally: manager.init(); or redirect to login
    return null;
}

function userSystemLogin() {
    const email = MemoryStore.get("login.email") || "";
    const pin = MemoryStore.get("login.pin") || "";

    console.log("SYSTEM LOGIN with:", email, pin);

    // Simulate login request
    // const m  anager2 = new WebConversationManager();
    manager.loginRequest(email, pin);
}

async function userCheckEmail(){
    const email = MemoryStore.get("login.email") || "";
    console.log("SYSTEM Check Email:", email);
    if(email){
        manager.checkEmail(email);
    }
}

function userSystemRegister() {
    const email = MemoryStore.get("signup.email") || "";
    const pin = MemoryStore.get("signup.pin") || "";
    const terms = MemoryStore.get("signup.terms") || "";

    console.log("SYSTEM REGISTER with:", email, pin, terms);

    manager.signupRequest(email, pin, terms);
}

//proceedToSignup
async function startCuriosityFlow(level){
    const email = MemoryStore.get("login.email") || "";
    alert(email);

    if (!email) {
        console.warn("Email missing.");
        return false;
    }

    try {
        const res = await fetch(`${CuriosityConfig.endpoint}/level/`+level, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ email })
        });

        //clear records
        await MemoryStore.clear();

        manager.resetCuriosities();

        const data = await res.json();
        
        manager.parseJwt(data.data).then(pData => {
            console.log('Level:: '+level, pData.data);
            manager.loadCuriosities(pData.data);
        });
        // alert('Finished getting '+level+' curiosity');
        console.warn('Current Curiosities', manager.getQueue());
        return;
    } catch (err) {
        console.error("Email check error:", err);
        return false;
    }
}
async function retryLogin(){
    alert('retryLogin');
    await MemoryStore.clear(); // wait until clear finishes
    await location.reload();
}

async function userRegister(){
    const email = MemoryStore.get("login.email") || "";
    const pin = MemoryStore.get("login.pin") || "";

    if (!email || !pin) {
        console.warn("Email or pin missing.");
        return false;
    }

    try {
        const res = await fetch(`${CuriosityConfig.endpoint}/auth/login`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ email, pin })
        });

        const data = await res.json();

        if (data.success && data.token) {
            console.log("Logged in", data.success);

            MemoryStore.set("auth.token", data, false);
            localStorage.setItem("auth.token", data.token);

            if(data.lnk){
                overlayLoader.show('Loading...');
                manager.setRedirectUrl(data.lnk);
            }

            return true;
        } else {
            console.warn("Login failed:", data.message || data);
            return false;
        }
    } catch (err) {
        console.error("Login error:", err);
        return false;
    }
}