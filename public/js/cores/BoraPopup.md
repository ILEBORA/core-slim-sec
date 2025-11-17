usage-scenarios.md
# BoraCore Popup System — Usage Scenarios

This document outlines how to use the unified popup system (`mPGs.openKlassPopup` and `KlassPopup`) for loading dynamic module forms, editors, previews, and custom dialogs.

---

## 1. Overview

The popup system supports:

- Inline HTML click handlers  
- Programmatic JavaScript calls  
- Chained builder pattern (OOP style)  
- Custom URL endpoints  
- Module-based default routes  
- Callback hooks for open, loaded, and close  
- Passing a callback pipe for result processing  

---

## 2. Basic Inline Usage

```html
<a data-e-click="mPGs.klassPopup('pages','manage',7,'settings')">
    Settings
</a>


This loads:

api/modules/pages/manage/form/settings/7

3. Programmatic Usage
mPGs.klassPopup('manage', 'pages', 7, 'edit');

4. Advanced Programmatic Usage (full control)
mPGs.openKlassPopup({
    klass: 'products',
    group: 'catalog',
    item: 12,
    tab: 'edit',
    openCall: () => console.log("Popup opening"),
    closeCall: () => console.log("Popup closed"),
    callbackPipe: (data) => console.log("Result:", data)
});

5. Using the Builder Class (OOP)
KlassPopup.show({
    klass: 'users',
    group: 'access',
    item: 4,
    tab: 'permissions'
});


Or with chaining:

new KlassPopup()
    .setClass('users')
    .setGroup('access')
    .setItem(4)
    .setTab('permissions')
    .setOpenCall(() => alert('Opening'))
    .build();

6. Custom Base Path (override default)

By default, popups load from:

api/modules/{klass}/{group}/form/{tab}/{item}


To override:

mPGs.openKlassPopup({
    base: 'api/forms',
    klass: 'newsletter',
    group: 'editor',
    item: 9,
    tab: 'preview'
});


Generates:

api/forms/newsletter/editor/form/preview/9

7. Completely Custom URL (skip auto-building)
mPGs.openKlassPopup({
    url: '/custom/popup/render?id=99'
});


This bypasses all route building logic.

8. Popup Callback Flow
Open callback

Triggered before content loads.

openCall: () => console.log('Opening popup')

Loaded callback

Triggered when remote HTML is injected.

(Internal — logs URL)

Close callback

Triggered on popup close:

closeCall: () => refreshList()

Callback Pipe

Used to return data back to caller:

callbackPipe: (submitted) => console.log(submitted)

9. Multiple Popups

To open using a different container:

mPGs.openKlassPopup({
    pop: 'profileEditor',
    klass: 'users',
    tab: 'edit'
});

10. Error Handling

The popup automatically logs:

Invalid URLs

Server errors

Missing HTML

Missing klass/group/item

(Enhancements available via centralized PopupManager)

11. Best Practices

Prefer KlassPopup.show() for readability

Use custom base paths for form engines, previews, or wizards

Avoid inline callbacks when possible; use named functions

Keep route definitions centralized if managing many modules

12. Future Extensions

The system is designed for optional expansion:

Multi-step popup wizard

PopupManager registry

Auto-reload parent list after form submit

Scroll locking and blur background

Return values with Promises instead of callbackPipe