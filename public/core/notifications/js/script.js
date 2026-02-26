formJourney.registerJourney('notifications.admin.send', function($form, done) {
	var url = $form.attr('action');
	var method = $form.attr('method') || 'POST';
	var data = $form.serialize();
	const btn = $form.find('button[type=submit]');
	const prevtext = btn.text();
        btn.prop('disabled', true).text('Processing...');

    // overlayLoader.show('Please wait...');

    // return 'Testing form';

	$.ajax({
		url: url,
		method: method,
		data: data,
		success: function(resp) {
            if(resp.success){
                $form[0].reset()
                alertBora.notify(resp.message??'Successful', 'success', 4);
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