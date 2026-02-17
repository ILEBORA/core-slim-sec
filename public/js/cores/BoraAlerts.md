// Modals
alertBora.alert('Saved successfully!').then(()=> console.log('closed'));
alertBora.confirm('<b>Delete file?</b>', { html: true, okText: 'Yes', cancelText: 'No'})
  .then(()=> console.log('confirmed'))
  .catch(()=> console.log('cancelled'));

// Prompt (simple)
alertBora.prompt('Your name:', { prompt: '<input name="name" class="bora-input" />' })
  .then(val => console.log(val.name || val.value));

// Toasts / notifications
alertBora.notify('Backup completed', 'success', 4);
alertBora.error('Failed to save', 5);

// Global config
alertBora.set('notifierPosition', 'top-right').set('notifierDelay', 4);

BoraAlerts v2 — Plugin Reference

Namespace: alertBoraV2
Plugin Name: BoraAlerts
Type: BoraSlim Plugin
Description: Minimal, modern alert, confirm, prompt & notification system.
Author: Fiki @ ILEBORA Technologies

⚙️ Initialization

Automatically registered through BoraSlim’s addPlugin().

var alertBoraV2 = BoraPlugins.BoraAlerts; // or simply alertBoraV2


No manual setup needed — the plugin initializes itself.

🧱 Core Methods
1. alertBoraV2.alert(message, [options])

Simple modal message.

alertBoraV2.alert('Operation successful!');


Options

Option	Type	Default	Description
html	Boolean	false	Render message as HTML
style	String	''	Add a custom CSS class to modal
okText	String	'OK'	OK button label
2. alertBoraV2.confirm(message, [options])

Confirmation dialog with OK and Cancel buttons.

alertBoraV2.confirm('Are you sure?', { okText: 'Yes', cancelText: 'No' })
  .then(() => console.log('Confirmed!'))
  .catch(() => console.log('Cancelled.'));

3. alertBoraV2.prompt(message, [options])

Prompt dialog that accepts input.

alertBoraV2.prompt('Enter your name:')
  .then(values => console.log(values.value))
  .catch(() => console.log('Cancelled.'));

4. alertBoraV2.notify(message, [type], [delay])

Lightweight toast notification.

alertBoraV2.notify('Backup completed!', 'success', 3);


Types: info, success, error, warning
Delay: time in seconds (default 3)

🔄 Helper Methods
p.loading(true|false)

Toggle a loading spinner and “Loading…” text on the OK button.

const p = alertBoraV2.confirm('Proceed?');
p.loading(true);
setTimeout(() => p.loading(false), 2000);

p.autoOk(seconds)

Automatically confirm after a delay, showing countdown on OK.

const p = alertBoraV2.confirm('Auto-confirming in 5s...');
p.autoOk(5).then(() => console.log('Auto confirmed!'));

p.autoCancel(seconds)

Automatically cancel after a delay, showing countdown on Cancel.

const p = alertBoraV2.confirm('Will cancel in 5s...');
p.autoCancel(5).catch(() => console.log('Cancelled automatically.'));

🌐 Global Settings
alertBoraV2.set(key, value)

Override default configuration at runtime.

alertBoraV2.set('labels', { ok: 'Yes', cancel: 'No' });
alertBoraV2.set('theme', 'dark');

🧩 Default Config Summary
Key	Default	Description
container	'body'	Where modals/toasts are appended
html	false	Whether to parse message as HTML
style	''	Custom modal class
okText	'OK'	Default OK text
cancelText	'Cancel'	Default Cancel text
position	'bottom-right'	Toast notification placement
labels	{ ok: 'OK', cancel: 'Cancel' }	i18n labels
animation	'fade'	Default show/hide animation
🧠 Notes

Uses $.Deferred() promises (works with .then() / .catch()).

Centers modals if $.fn.center() exists.

Non-blocking, fades in/out smoothly.

Integrates seamlessly with BoraSlim plugin system.