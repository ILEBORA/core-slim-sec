
# 🧩 **BoraEvents v4 — Documentation**

**Smart Declarative Event System with Auto Argument Mapping**

---

## 📜 Overview

**BoraEvents** simplifies DOM event binding by allowing you to declare event-driven behaviors directly in HTML attributes — no repetitive JavaScript setup needed.

It supports:
- `data-e` → Generic click handler  
- `data-e-<event>` → Specific event handlers (e.g., `data-e-change`)  
- `data-e-trigger` → Hook trigger calls via `appHooks`  
- Auto-mapped arguments (e.g., `${val}`, `${text}`, `${attr.href}`)  
- Optional allowlist for safe execution (`BoraEvents.allow`)

---

## ⚙️ Initialization

Automatically runs on `$(document).ready()`

```js
$(document).ready(() => BoraEvents.init());
```

You don’t need to call it manually unless reloading dynamic AJAX content.

If needed:
```js
BoraEvents.init(); // Rebinds events after content load
```

---

## 💡 Supported Attributes

| Attribute | Description | Example |
|------------|--------------|----------|
| `data-e` | Default click event function call | `<button data-e="sayHello()">Click Me</button>` |
| `data-e-click` | Explicit event type binding | `<div data-e-click="doSomething(1, 2)">...</div>` |
| `data-e-change` | Triggered on input change | `<input data-e-change="updateField(${val})">` |
| `data-e-trigger` | Calls an appHook trigger | `<button data-e-trigger="app.logout">Logout</button>` |

---

## 🎯 Example Usage

### 1️⃣ Basic Inline Function Call
```html
<button data-e="sayHello('Fiki')">Say Hello</button>
```

```js
function sayHello(name) {
  alert('Hello, ' + name);
}
```

---

### 2️⃣ With Auto-Mapped Arguments
Auto arguments replace `${...}` placeholders with element values.

| Placeholder | Description | Example |
|--------------|--------------|----------|
| `${val}` | The element’s `.val()` | `<input data-e-change="updateValue(${val})">` |
| `${text}` | The element’s `.text()` | `<button data-e-click="logText(${text})">Click</button>` |
| `${html}` | The element’s `.html()` | `<div data-e-click="showHTML(${html})"></div>` |
| `${attr.href}` | An attribute value | `<a data-e-click="openLink(${attr.href})"></a>` |
| `${data.id}` | Element’s data attribute | `<div data-id="42" data-e-click="loadUser(${data.id})"></div>` |
| `${prop.checked}` | Element’s property | `<input type="checkbox" data-e-change="toggle(${prop.checked})">` |

---

### 3️⃣ Triggering appHooks

```html
<button data-e-trigger="app.logout">Logout</button>
```

When clicked, it will call:
```js
appHooks.callHook('user.logout', { e, $el, eventType });
```

If `appHooks.hasHook('user.logout')` returns false → a warning is shown.

---

### 4️⃣ Custom Events

You can manually trigger custom events using:

```js
BoraEvents.triggerCustom($('#myDiv'), 'custom', { key: 'value' });
```

Then bind in HTML:
```html
<div data-e-custom="handleCustom(${data.key})"></div>
```

---

## 🛡️ Safe Execution

If you want to restrict which functions can be executed via `data-e`, define:

```js
BoraEvents.allow = ['sayHello', 'updateValue', 'toggle'];
```

Any call not in the allowlist will be blocked:
```
Blocked call to non-allowed function: deleteAccount
```

---

## 🔗 Integration with `appHooks`

If you have an event-based architecture using `appHooks`:

```js
appHooks.register('user.logout', function(ctx) {
    console.log('Logging out...', ctx.$el);
});
```

Then the HTML below works automatically:
```html
<button data-e-trigger="app.logout">Logout</button>
```

---

## 🚫 Error Handling

- Logs missing functions or triggers in console.
- Alerts user if trigger not found.
- Handles parsing and argument resolution safely.

---

## 📦 Version Info

**Version:** `v4`  
**License:** MIT  
**Author:** IleBora Technologies  
**Framework:** BoraSlim UI  

---

## 🧠 Pro Tips

- Use `data-e-*` for all events you want to auto-bind.
- Use `${}` arguments for dynamic mappings.
- If you load new content via AJAX → call `BoraEvents.init()` again.
- Combine with `appHooks` for modular reactive design.
- Use an allowlist for enhanced security in public-facing components.
