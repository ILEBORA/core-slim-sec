/**
 * BoraEvents v4
 * ------------------------------------------------------
 * Smart declarative event system with auto argument mapping.
 * 
 * - data-e / data-e-<event> / data-e-trigger
 * - Auto arg placeholders: ${val}, ${text}, ${html}, ${attr.href}, ${data.id}, etc.
 * - Integrates with appHooks
 */

(function ($) {

    const BoraEvents = {

        supportedEvents: [
            'click', 'change', 'input', 'submit', 'hover',
            'focus', 'blur', 'keydown', 'keyup', 'dblclick',
            'contextmenu', 'custom'
        ],

        allow: null, // optional allowlist

        init() {
            // Fallback for generic data-e / data-e-trigger
            $(document).on('click', '[data-e], [data-e-trigger]', function (e) {
                BoraEvents.handleEvent($(this), e, 'click');
            });

            // Auto-bind for each supported event
            BoraEvents.supportedEvents.forEach(eventType => {
                $(document).on(eventType, `[data-e-${eventType}]`, function (e) {
                    BoraEvents.handleEvent($(this), e, eventType);
                });
            });

            console.log('%c BoraEvents v4 initialized with smart args', 'color:#14b8a6;font-weight:bold;');
        },

        handleEvent($el, e, eventType = 'click') {
            const fnCall = $el.attr(`data-e-${eventType}`) || $el.attr('data-e');
            const trigger = $el.attr('data-e-trigger');

            if (fnCall) BoraEvents.resolveFunction(fnCall, e, $el, eventType);
            else if (trigger) BoraEvents.resolveTrigger(trigger, e, $el, eventType);
        },

        resolveFunction(fnCall, e, $el, eventType) {
            try {
                const fn = fnCall.split('(')[0].trim();
                const argsString = fnCall.match(/\((.*)\)/);
                let args = [];

                if (argsString && argsString[1]) {
                    args = argsString[1]
                        .split(',')
                        .map(a => BoraEvents.resolveArg(a.trim(), $el));
                }

                if (BoraEvents.allow && !BoraEvents.allow.includes(fn)) {
                    console.warn(`Blocked call to non-allowed function: ${fn}`);
                    return;
                }

                const fnParts = fn.split('.');
                let ctx = window;
                for (let i = 0; i < fnParts.length - 1; i++) {
                    ctx = ctx[fnParts[i]];
                    if (!ctx) throw new Error(`Context not found: ${fnParts.slice(0, i + 1).join('.')}`);
                }

                const method = ctx[fnParts.pop()];
                if (typeof method === 'function') {
                    method.apply(ctx, args.length ? args : [e, $el, eventType]);
                } else {
                    console.warn(`Function not found: ${fn}`);
                }

            } catch (err) {
                console.error('Error executing data-e function:', err);
            }
        },

        resolveArg(rawArg, $el) {
            if (!rawArg) return null;

            // Literal string or number
            if (/^['"].*['"]$/.test(rawArg)) return rawArg.replace(/^['"]|['"]$/g, '');
            if (!isNaN(rawArg)) return Number(rawArg);

            // Smart mapping patterns
            if (rawArg.startsWith('${') && rawArg.endsWith('}')) {
                const key = rawArg.slice(2, -1).trim(); // remove ${ }

                // Patterns
                if (key === 'val') return $el.val();
                if (key === 'text') return $el.text();
                if (key === 'html') return $el.html();

                // Attribute: ${attr.href}
                if (key.startsWith('attr.')) return $el.attr(key.replace('attr.', ''));

                // Data attribute: ${data.id}
                if (key.startsWith('data.')) return $el.data(key.replace('data.', ''));

                // Property: ${prop.checked}
                if (key.startsWith('prop.')) return $el.prop(key.replace('prop.', ''));

                // fallback: element context
                return $el.attr(key) || $el.data(key) || null;
            }

            return rawArg;
        },

        resolveTrigger(trigger, e, $el, eventType) {
            // alert(trigger);
            if (typeof appHooks !== 'undefined' && typeof appHooks.callHook === 'function') {
                const exists = appHooks.hasHook ? appHooks.hasHook(trigger) : true;
                if (exists) {
                    appHooks.callHook(trigger, { e, $el, eventType });
                } else {
                    console.warn(`Trigger "${trigger}" not registered.`);
                    alert(`Trigger "${trigger}" not found.`);
                }
            } else {
                console.warn('appHooks system not available.');
            }
        },

        triggerCustom($target, name = 'custom', data = {}) {
            $target.trigger(name, data);
        }
    };

    window.BoraEvents = BoraEvents;
    $(document).ready(() => BoraEvents.init());

})(jQuery);


$.fn.center = function () {
    this.css("position", "fixed");
    this.css("top", ($(window).height() - this.outerHeight()) / 2 + "px");
    this.css("left", ($(window).width() - this.outerWidth()) / 2 + "px");
    return this;
};