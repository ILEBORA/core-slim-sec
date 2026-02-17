/**
 * BoraSlim LiveBinder 2050++ Edition
 * ----------------------------------
 * - Self-healing event delegation (AJAX + MutationObserver)
 * - Auto-initialization of elements via attributes
 * - Namespaced + contextual control
 */

(function($) {

    const LiveBinder = {
        context: document,
        namespace: 'live',
        observers: new Map(),
        autoAttr: ['data-lvinit', 'data-auto', 'bora-lvinit'],

        bind(selector, event, handler, opts = {}) {
            const ctx = opts.context || LiveBinder.context;
            const ns = opts.namespace || LiveBinder.namespace;
            const evt = `${event}.${ns}`;
            $(ctx).off(evt, selector).on(evt, selector, function(e) {
                handler.call(this, e, $(this));
            });
            return this;
        },

        unbind(ns = LiveBinder.namespace, ctx = LiveBinder.context) {
            $(ctx).off(`.${ns}`);
            return this;
        },

        rebindAll() {
            $(document).trigger('livebinder:rebind');
            return this;
        },

        observe(container = document, opts = {}) {
            if (LiveBinder.observers.has(container)) return;

            const observer = new MutationObserver(mutations => {
                mutations.forEach(m => {
                    if (m.addedNodes.length) {
                        $(document).trigger('livebinder:rebind', [m.addedNodes]);
                        LiveBinder.autoInit(m.addedNodes);
                    }
                });
            });

            observer.observe(container, { childList: true, subtree: true });
            LiveBinder.observers.set(container, observer);

            // Also trigger auto-init on initial load
            LiveBinder.autoInit(container.querySelectorAll('*'));
        },

        unobserve(container = document) {
            const obs = LiveBinder.observers.get(container);
            if (obs) {
                obs.disconnect();
                LiveBinder.observers.delete(container);
            }
        },

        autoInitO(nodes) {
            $(nodes).each(function() {
                if (this.nodeType !== 1) return; // skip non-elements
                LiveBinder.autoAttr.forEach(attr => {
                    const fnName = this.getAttribute(attr);
                    if (fnName && typeof window[fnName] === 'function') {
                        try { window[fnName](this); } catch (e) { console.warn(e); }
                    } 
                    else if (fnName && window.BoraSlim && typeof BoraSlim[fnName] === 'function') {
                        try { BoraSlim[fnName](this); } catch (e) { console.warn(e); }
                    }
                });
            });
        },

        autoInit(nodes) {
            $(nodes).each(function() {
                if (this.nodeType !== 1) return; // skip non-elements

                LiveBinder.autoAttr.forEach(attr => {
                    const fnName = this.getAttribute(attr);
                    if (!fnName) return;

                    // read optional args
                    let args = {};
                    const argAttr = this.getAttribute('data-lvargs');
                    if (argAttr) {
                        try { args = JSON.parse(argAttr); } 
                        catch(e) { console.warn('Invalid data-lvargs JSON on', this, e); }
                    }

                    // call global or BoraSlim function
                    const invoke = (fn, ctx) => {
                        try { fn.call(ctx, this, args); } 
                        catch (e) { console.warn(e); }
                    };

                    if (typeof window[fnName] === 'function') {
                        invoke(window[fnName], window);
                    } else if (window.BoraSlim && typeof BoraSlim[fnName] === 'function') {
                        invoke(BoraSlim[fnName], BoraSlim);
                    }
                });
            });
        },

        setDefaults(options = {}) {
            if (options.context) LiveBinder.context = options.context;
            if (options.namespace) LiveBinder.namespace = options.namespace;
            return this;
        }
    };

    $.liveBind = (selector, event, handler, opts) => LiveBinder.bind(selector, event, handler, opts);
    $.liveUnbind = (ns, ctx) => LiveBinder.unbind(ns, ctx);
    $.liveObserve = (container, opts) => LiveBinder.observe(container, opts);
    $.liveUnobserve = (container) => LiveBinder.unobserve(container);

    $(document).on('ajaxComplete', () => LiveBinder.rebindAll());

    // Default observer on document
    LiveBinder.observe(document);

    // Integrate with BoraSlim if present
    if (typeof window.BoraSlim !== 'undefined') {
        BoraSlim.live = $.liveBind;
        BoraSlim.unlive = $.liveUnbind;
        BoraSlim.observe = $.liveObserve;
        BoraSlim.unobserve = $.liveUnobserve;
        BoraSlim.autoInit = LiveBinder.autoInit.bind(LiveBinder);
    }

})(jQuery);