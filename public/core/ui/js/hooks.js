__BORA_REGISTER_PLUGIN__('ui.hooks', async (scope) => {

    const hooks = await scope.getService('hooks');
    const uiActions = await scope.getService('ui.actions');
    const uiStack = await scope.getService('uiStack');

    // alert('Ui Hooks');
    // Register a beforeSubmit hook
    hooks.add("form:beforeSubmit", ($form) => {
        console.log("Before submitting:", $form.attr('id'));
        if ($form.closest('.bora-alert').length) {
            console.log("Inside popup form - letting AJAX handle it");
            return true;
        }
        // Return false to cancel submit
        if ($form.find("input[name='email']").val() === "") {
            alert("Email is required!");
            return false;
        }
    });

    // Register an afterSubmit hook
    hooks.add("form:afterSubmit", async ($form, resp) => {
        console.log("Form submitted:", $form.attr('id'), resp);
        // e.g., show a toast or update Ui
        if (resp.message){
            var type = resp.success ? 'success' : 'error';
            alertBora.notify(resp.message, type, 4);
        }

        if(resp.redirect){
            // overlayLoader.show('Loading...');
            Bora.navigate(resp.redirect);
        }

        if(resp.esc){
            // alert('esc');
            uiStack.closeTop();
            await __BORA_APP__.service('hooks')?.call('esc');
        }

        if(resp.success){
            // $form.reset();
            $form[0]?.reset();
        }
    });
    // alert('here');

    class BoraEncryptor {
        static async encrypt(text, publicKey) {
            if (!text || !publicKey) return null;

            // Convert plain text to UTF-8 bytes
            const encoded = new TextEncoder().encode(text);

            // Encrypt with RSA-OAEP
            const encryptedBuffer = await crypto.subtle.encrypt(
                { name: "RSA-OAEP" },
                publicKey,
                encoded
            );

            // Convert ArrayBuffer → Base64
            const encryptedBytes = new Uint8Array(encryptedBuffer);
            let binary = "";
            encryptedBytes.forEach(byte => binary += String.fromCharCode(byte));

            return btoa(binary);
        }
    }

    // Register journeys dynamically
    // Login
    formJourney.registerJourney('login', function($form, done) {
        var url = $form.attr('action');
        var method = $form.attr('method') || 'POST';
        const formData = new FormData($form[0]);
        const btn = $form.find('button[type=submit]');
        const password = formData.get('password');
        formData.set("password", btoa(password));
        const data = new URLSearchParams(formData).toString();
        const prevtext = btn.text();
            btn.prop('disabled', true).text('Processing...');
        
        // overlayLoader.show('Please wait...');

        $.ajax({
            url: url,
            method: method,
            data: data,
            success: function(resp) {
                if(resp.success){
                    alertBora.notify('Login Successful', 'success', 4);
                    if(resp.redirect){
                        // overlayLoader.show('Loading...');
                        appUI.content.loadPage(resp.redirect);
                    }
                    btn.prop('disabled', false).text('Continue');
                }else{
                    alertBora.notify(resp.message, 'error', 5);
                    btn.prop('disabled', false).text(prevtext);
                }
                // btn.prop('disabled', false).text('Continue');
                if (typeof done === 'function') done(resp);
            },
            error: function(err) {
                overlayLoader.hide();
                console.error('Form error', err);
                alertBora.notify(err, 'error', 15);
                btn.prop('disabled', false).text(prevtext);
                if (typeof done === 'function') done(err);
            }
        });
    });

    formJourney.registerJourney('mfaselect', function($form, done) {
        // alert('login here');
        var url = $form.attr('action');
        var method = $form.attr('method') || 'POST';
        var data = $form.serialize();
        const btn = $form.find('button[type=submit]');
        const prevtext = btn.text();
            btn.prop('disabled', true).text('Processing...');

        // overlayLoader.show('Please wait...');

        $.ajax({
            url: url,
            method: method,
            data: data,
            success: function(resp) {
                // alert('login here');
                if(resp.success){
                    // alertBora.notify('Code Sent', 'success', 4);
                    
                    if(resp.redirect){
                        // overlayLoader.show('Loading...');
                        // redirectTo(resp.redirect);
                        appUI.content.loadPage(resp.redirect);
                    }

                }else{
                    alertBora.notify(resp.message, 'error', 5);

                    if(resp.redirect){
                        // overlayLoader.show('Loading...');
                        // redirectTo(resp.redirect);
                        appUI.content.loadPage(resp.redirect);
                    }
                }

                if (typeof done === 'function') done(resp);
            },
            error: function(err) {
                // overlayLoader.hide();
                console.error('Form error', err);
                alertBora.notify(err, 'error', 5);
                if (typeof done === 'function') done(err);
            }
        });
    });

    formJourney.registerJourney('mfaverify', function($form, done) {
        // alert('login here');
        var url = $form.attr('action');
        var method = $form.attr('method') || 'POST';
        var data = $form.serialize();
        const btn = $form.find('button[type=submit]');
        const prevtext = btn.text();
            btn.prop('disabled', true).text('Processing...');

        // overlayLoader.show('Please wait...');

        $.ajax({
            url: url,
            method: method,
            data: data,
            success: function(resp) {
                // alert('login here');
                if(resp.success){
                    alertBora.notify('Verified Successful', 'success', 4);
                    // console.log("Logged in", data.success);

                    if(resp.redirect){
                        if(typeof authChannel !== 'undefined'){
                            authChannel.postMessage({cmd:'login',usr:rd('bID'), lnk: this.lnk});
                        }
                        // overlayLoader.show('Loading...');
                        appHooks.callHook('page.beforeLoad', resp.redirect);
                        redirectTo(resp.redirect);
                    }

                }else{
                    alertBora.notify(resp.message, 'error', 5);
                    btn.prop('disabled', false).text(prevtext);
                }

                if (typeof done === 'function') done(resp);
            },
            error: function(err) {
                overlayLoader.hide();
                btn.prop('disabled', false).text(prevtext);
                console.error('Form error', err);
                alertBora.notify(err, 'error', 5);
                if (typeof done === 'function') done(err);
            }
        });
    });

    uiActions.register('app.mfa.cancel',function(){
        new CallBora("api/modules/ui/access/cancelMfa")
            .setMethod("POST")
            .setParams({})
            .setCallback((res) => {
                appUI.content.loadPage('account/login');
            })
            .setDone(() => {
                console.log("Request finished");
            })
            .setError((xhr) => console.error("Error:", xhr))
            .build();
    });

    //Save 
    formJourney.registerJourney('save', function($form, done) {
        var url = $form.attr('action');
        var method = $form.attr('method') || 'POST';
        var data = $form.serialize();

        $.ajax({
            url: url,
            method: method,
            data: data,
            success: function(resp) {
                // alert('login here');
                console.log('Default form saved', resp);
                if (typeof done === 'function') done(resp);
            },
            error: function(err) {
                console.error('Form error', err);
                if (typeof done === 'function') done(err);
            }
        });
    });

    //Delete
    formJourney.registerJourney('delete', function($form, done) {
        var url = $form.attr('action');
        var method = $form.attr('method') || 'POST';
        var data = $form.serialize();

        $.ajax({
            url: url,
            method: method,
            data: data,
            success: function(resp) {
                // alert('login here');
                console.log('Default form saved', resp);
                if (typeof done === 'function') done(resp);
            },
            error: function(err) {
                console.error('Form error', err);
                if (typeof done === 'function') done(err);
            }
        });
    });

    //Password forgot journey
    // Forgot Password
    formJourney.registerJourney('forgot', function($form, done) {
        var url = $form.attr('action');
        var method = $form.attr('method') || 'POST';
        const formData = new FormData($form[0]);
        const btn = $form.find('button[type=submit]');
        const prevtext = btn.text();

        btn.prop('disabled', true).text('Processing...');
        overlayLoader.show('Sending reset link...');

        $.ajax({
            url: url,
            method: method,
            data: new URLSearchParams(formData).toString(),
            success: function(resp) {
                overlayLoader.hide();

                if (resp.success) {
                    alertBora.notify(resp.message || 'Reset link sent to your email', 'success', 5);

                    if (resp.redirect) {
                        appUI.content.loadPage(resp.redirect);
                    }
                    btn.prop('disabled', false).text('Continue');
                } else {
                    alertBora.notify(resp.message || 'Error sending reset link', 'error', 5);
                    btn.prop('disabled', false).text(prevtext);
                }

                if (typeof done === 'function') done(resp);
            },
            error: function(err) {
                overlayLoader.hide();
                console.error('Form error', err);
                alertBora.notify('Network or server error', 'error', 10);
                btn.prop('disabled', false).text(prevtext);

                if (typeof done === 'function') done(err);
            }
        });
    });

    // Reset Password Journey
    formJourney.registerJourney('reset', function($form, done) {
        var url = $form.attr('action');
        var method = $form.attr('method') || 'POST';
        const formData = new FormData($form[0]);
        const btn = $form.find('button[type=submit]');
        const password = formData.get('password');
        const passwordConfirm = formData.get('password_confirm');

        // Basic password strength check
        if (password.length < 8 || !/\d/.test(password)) {
            alertBora.notify('Password must be at least 8 characters and include a number.', 'error', 5);
            return;
        }

        if (password !== passwordConfirm) {
            alertBora.notify('Passwords do not match.', 'error', 5);
            return;
        }

        formData.set("password", btoa(password)); // encode password
        formData.set("password_confirm", btoa(password)); // encode password

        const data = new URLSearchParams(formData).toString();
        const prevtext = btn.text();
        btn.prop('disabled', true).text('Processing...');

        $.ajax({
            url: url,
            method: method,
            data: data,
            success: function(resp) {
                if(resp.success){
                    alertBora.notify('Password updated successfully.', 'success', 4);
                    if(resp.redirect){
                        appUI.content.loadPage(resp.redirect);
                    }
                } else {
                    alertBora.notify(resp.message, 'error', 5);
                    if(resp.redirect){
                        appUI.content.loadPage(resp.redirect);
                    }
                }
                btn.prop('disabled', false).text(prevtext);
                if (typeof done === 'function') done(resp);
            },
            error: function(err) {
                console.error('Form error', err);
                alertBora.notify('An error occurred. Please try again.', 'error', 15);
                btn.prop('disabled', false).text(prevtext);
                if (typeof done === 'function') done(err);
            }
        });
    });


    formJourney.registerJourney('register', function($form, done) {
        var url = $form.attr('action');
        var method = $form.attr('method') || 'POST';
        const formData = new FormData($form[0]);
        const btn = $form.find('button[type=submit]');
        const prevtext = btn.text();

        const password = formData.get('password');
        const confirmPassword = formData.get('password_confirm');

        // Basic password strength check
        if (password.length < 8 || !/\d/.test(password)) {
            alertBora.notify('Password must be at least 8 characters and include a number.', 'error', 5);
            return;
        }

        if (password !== confirmPassword) {
            alertBora.notify('Passwords do not match.', 'error', 5);
            return;
        }

        // Encode password before sending
        formData.set("password", btoa(password));
        formData.set("password_confirm", btoa(confirmPassword));

        const data = new URLSearchParams(formData).toString();
        btn.prop('disabled', true).text('Creating Account...');

        $.ajax({
            url: url,
            method: method,
            data: data,
            success: function(resp) {
                if(resp.success) {
                    alertBora.notify('Account created successfully!', 'success', 4);
                    if(typeof authChannel !== 'undefined'){
                        authChannel.postMessage({cmd:'login',usr:rd('bID'), lnk: this.lnk});
                    }
                    if (resp.redirect) {
                        appUI.content.loadPage(resp.redirect);
                    }

                    if (resp.reload) {
                        redirectTo(resp.reload, true);
                    }

                    btn.text('Continue');
                } else {
                    alertBora.notify(resp.message, 'error', 6);
                    btn.text(prevtext);

                    if (resp.redirect) {
                        appUI.content.loadPage(resp.redirect);
                    }

                    if (resp.reload) {
                        redirectTo(resp.reload, true);
                    }
                }

                btn.prop('disabled', false);
                if (typeof done === 'function') done(resp);
            },
            error: function(err) {
                console.error('Form error', err);
                alertBora.notify('Something went wrong. Try again later.', 'error', 12);
                btn.prop('disabled', false).text(prevtext);

                if (typeof done === 'function') done(err);
            }
        });
    });

});