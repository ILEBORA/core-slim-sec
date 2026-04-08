# Bora UI Dismiss Pattern (Quick Reference)

A simple rule to manage UI elements that can be closed with **ESC**, **Back button**, or **clicking elsewhere**.

---

# Mental Model


If UI can be dismissed
→ create dismissable instance

To close UI
→ instance.close()


You **never manually unregister** from the stack.

The dismissable instance handles that automatically.

---

# Core Services

## uiStack
Global stack of dismissable UI elements.

Handles:

- ESC key
- Browser back button
- Layered UI closing

Example stack:


[ dropdown
popup
modal ]


ESC closes **top item first**.

---

## ui.dismissable

Creates a dismissable instance.


const dismissable = app.service('ui.dismissable');

const instance = dismissable.create(()=>{
closeUI();
});


When closed:


instance.close()
↓
closeUI()
↓
uiStack.unregister(instance)


---

# Example 1 — Reaction Dropdown

### Open

```javascript
$(document).on('click', '.reaction-trigger', async function(e){

    e.preventDefault();

    const uiStack = await __BORA_APP__.service('uiStack');
    const dismissable = await __BORA_APP__.service('ui.dismissable');

    const $box = $(this).closest('.reaction-box');

    if($box.hasClass('open')){
        $box.data('dismissInstance')?.close();
        return;
    }

    // close other dropdown
    uiStack.closeTop();

    $box.addClass('open');

    const instance = dismissable.create(()=>{
        $box.removeClass('open');
        $box.removeData('dismissInstance');
    });

    $box.data('dismissInstance', instance);

});
Close after reaction
$box.data('dismissInstance')?.close();
Example 2 — Sidebar
Open
const dismissable = await scope.getService('ui.dismissable');

let sidebarInstance = null;

function toggleSidebar(){

    const opening = !sidebar.hasClass('sideActive');

    if(opening){

        sidebar.addClass('sideActive');

        sidebarInstance = dismissable.create(()=>{
            closeSidebar();
        });

    } else {

        sidebarInstance?.close();
    }

}
Example 3 — Profile Dropdown
$(document).on('click', '.mini-photo-wrapper', function(e){

    e.stopPropagation();

    const dismissable = await scope.getService('ui.dismissable');

    if(dropMenu.hasClass('is-active')){
        dropMenu.data('dismissInstance')?.close();
        return;
    }

    dropMenu.addClass('is-active');

    const instance = dismissable.create(()=>{
        dropMenu.removeClass('is-active');
        dropMenu.removeData('dismissInstance');
    });

    dropMenu.data('dismissInstance', instance);

});
Layered Behavior

Example stack:

[ sidebar
  profileMenu
  reactionDropdown ]

ESC presses:

ESC → reactionDropdown closes
ESC → profileMenu closes
ESC → sidebar closes
Rules
1️⃣ If UI opens
dismissable.create(...)
2️⃣ If UI closes manually
instance.close()
3️⃣ Never manually unregister
❌ uiStack.unregister(...)

Only the dismissable instance handles that.

Benefits

✔ ESC closes UI
✔ Back button closes UI
✔ UI layers stack properly
✔ No manual cleanup logic
✔ Works across all plugins

Bora UI Pattern
uiStack
   ↑
popup
dropdown
sidebar
reaction picker
context menu
drawer

Everything becomes dismissable layers.