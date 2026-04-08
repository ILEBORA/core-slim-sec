Supported Features
1. Basic binding
<span data-bind="user.name"></span>
2. Two-way input binding
<input data-bind="user.name">

✔ Updates UI
✔ Updates state on typing

3. Attribute binding
<img data-bind="user.avatar" data-bind-attr="src">
<a data-bind="link.url" data-bind-attr="href"></a>
4. HTML binding
<div data-bind="post.content" data-bind-html="true"></div>
🧠 Usage Pattern (your system)
Initial mount
const dom = await scope.getPlugin('DomReactivity');
dom.mount(document);
After AJAX load (important for you)
$('#page_content').html(newHtml);

dom.mount('#page_content');
Optional cleanup before replacing content
dom.destroy('#page_content');
⚠️ Key Design Decisions (intentional)
1. data-bound flag

Prevents:

duplicate subscriptions
memory leaks
double updates
2. Scoped mounting
mount(container)

Fits perfectly with your:

AJAX page system
modular rendering
partial reloads
3. Unsubscribe support

You’re now safe to:

destroy UI fragments
re-render cleanly
4. Change detection
if(newVal !== current)

Prevents:

infinite loops
redundant state churn
🚀 Where this becomes powerful (for YOU specifically)

Given your ecosystem:

state → source of truth
DomReactivity → DOM sync
lvui → cross-tab sync

You can evolve this into:

🔁 Full reactive loop
User input → state.set → lvui sync → other tabs → DomReactivity → UI update

That’s essentially:

a lightweight distributed reactive UI system

🧪 Suggested next step (high ROI)

If you're stabilizing before deployment, add just one more feature:

👉 data-bind-class
<div data-bind="status" data-bind-class="active"></div>
if($el.data('bind-class')){
    const cls = $el.data('bind-class');
    $el.toggleClass(cls, !!value);
}