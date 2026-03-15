async function loadAndPrompt(url, fallbackHtml = "<p>Content not available.</p>") {
    try {
        const res = await fetch(url, { headers: { "Accept": "text/html" } });

        if (!res.ok) throw new Error("Not found / bad response");

        const html = await res.text();
        return alertBora.prompt(html, { html: true });
        
    } catch (err) {
        console.warn("Failed to load HTML:", err.message);
        return alertBora.prompt(fallbackHtml, { html: true });
    }
}

async function loadAndPromptDelayed(url, fallbackHtml = "<p>Not found.</p>") {
   
    const modal = alertBora.prompt(`
        <div class="bora-loading">
            <div class="spinner"></div>
            Loading form...
        </div>
    `, { 
        html:true 
    }).then(function(det) {
        console.log('VALUES:: ', det);
        // det['typ'] = typ;
        // det['itm'] = itm;
        // alert('Here');
     });

    try {
        const res = await fetch(url, { headers: {"Accept":"text/html"} });
        if (!res.ok) throw new Error("Failed");

        const html = await res.text();
        alertBora.update(html);  // ⬅️ HERE
        return modal;            // keeps same promise chain

    } catch (err) {
        alertBora.update(fallbackHtml); // ⬅️ fallback swap
        return modal;
    }
}


let currentPopup = null;

async function openPostPopup() {
    // currentPopup = await mPGs.klassPopup('activity', 'timeline', null, 'add');
    const popup = window.__BORA_APP__?.service?.('popup');
    if (!popup) return;

    popup.open({
        mode:   'form',
        module: 'activity',
        group:  'timeline',
        view:   'add',
        id:     null,
        tab:    'add',
        size:   'md',
        meta:   null
    });
}

function closePostPopup() {
    if(currentPopup && typeof currentPopup.close === "function"){
        currentPopup.close();
        currentPopup = null;
    }
}

formJourney.registerJourney('timeline.add', function($form, done) {
    const url = $form.attr('action');
    const method = $form.attr('method') || 'POST';
    const btn = $form.find('button[type=submit]');
    const prevtext = btn.text();
    btn.prop('disabled', true).text('Processing...');

    // If files exist, use FormData; otherwise fallback to serialize
    let hasFiles = $form.find('input[type="file"]').length > 0;
    let data = null;
    let ajaxOptions = {
        url,
        method,
        success(resp){
            if(resp.success){
                alertBora.notify('Post Shared', 'success', 4);
                if(resp.redirect){
                    if(typeof authChannel !== 'undefined'){
                        authChannel.postMessage({cmd:'login', usr: rd('bID'), lnk: resp.redirect});
                    }
                    redirectTo(resp.redirect);
                }
                btn.prop('disabled', false).text(prevtext);
                closePostPopup();
                //Add to timeline
                ActivityFeed.render(resp.data, false);
            } else {
                alertBora.notify(resp.message || 'Unexpected error', 'error', 5);
                btn.prop('disabled', false).text(prevtext);
            }
            if(typeof done === 'function') done(resp);
        },
        error(err){
            btn.prop('disabled', false).text(prevtext);
            alertBora.notify('Network / Server error', 'error', 5);
            if(typeof done === 'function') done(err);
        }
    };

    if(hasFiles){
        data = new FormData($form[0]);
        ajaxOptions.data = data;
        ajaxOptions.processData = false;
        ajaxOptions.contentType = false;
    } else {
        data = $form.serialize();
        ajaxOptions.data = data;
    }

    $.ajax(ajaxOptions);
});


formJourney.registerJourney('timeline.add0', function($form, done) {
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
            if(resp.success){
                alertBora.notify('Post Shared', 'success', 4);
                if(resp.redirect){
                    if(typeof authChannel !== 'undefined'){
                        authChannel.postMessage({cmd:'login',usr:rd('bID'), lnk: this.lnk});
                    }
                    redirectTo(resp.redirect);
                }
                btn.prop('disabled', false).text(prevtext);
                closePostPopup();
            }else{
                alertBora.notify(resp.message, 'error', 5);
				btn.prop('disabled', false).text(prevtext);
            }

			if (typeof done === 'function') done(resp);
		},
		error: function(err) {
			btn.prop('disabled', false).text(prevtext);
			// console.error('Form error', err);
            alertBora.notify(err, 'error', 5);
			if (typeof done === 'function') done(err);
		}
	});
});
// alert('Activity');