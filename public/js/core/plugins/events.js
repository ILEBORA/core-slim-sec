__BORA_REGISTER_PLUGIN__('events', async function(scope){

    // const $ = await scope.getService('jquery');
    const hooks = await scope.getService('hooks');
    const config = await scope.config || {};
    console.log('[events] mounted');
    const BoraEvents = {

        supportedEvents: [
            'click', 'change', 'input', 'submit', 'hover',
            'focus', 'blur', 'keydown', 'keyup', 'dblclick',
            'contextmenu', 'custom'
        ],

        allow: null,

        init(){

            // Generic fallback
            $(document).on('click', '[data-e], [data-e-trigger]', function(e){
                BoraEvents.handleEvent($(this), e, 'click');
            });

            // Auto-bind declared events
            BoraEvents.supportedEvents.forEach(eventType => {

                $(document).on(eventType, `[data-e-${eventType}]`, function(e){
                    BoraEvents.handleEvent($(this), e, eventType);
                });

            });

            if(config.dev){
                console.log('%c BoraEvents v5 (runtime)', 'color:#14b8a6;font-weight:bold;');
            }
        },

        handleEvent($el, e, eventType = 'click'){

            const fnCall = $el.attr(`data-e-${eventType}`) || $el.attr('data-e');
            const trigger = $el.attr('data-e-trigger');

            if(fnCall){
                BoraEvents.resolveFunction(fnCall, e, $el, eventType);
            }
            else if(trigger){
                BoraEvents.resolveTrigger(trigger, e, $el, eventType);
            }
        },

        resolveFunction(fnCall, e, $el, eventType){

            try{

                const app = window.__BORA_APP__;
                const securityMode = scope.config?.securityMode || 'loose';
                const dev = scope.config?.dev;

                const fn = fnCall.split('(')[0].trim();
                const argsString = fnCall.match(/\((.*)\)/);
                let args = [];

                if(argsString && argsString[1]){
                    args = argsString[1]
                        .split(',')
                        .map(a => BoraEvents.resolveArg(a.trim(), $el));
                }

                /* =================================================
                STRICT MODE
                ================================================= */

                if(securityMode === 'strict'){

                    const parts = fn.split('.');
                    const rootName = parts[0];

                    let ctx = null;

                    // 1️⃣ Explicitly allowed global alias
                    if(rootName === 'alertBora' && window.alertBora){
                        ctx = window.alertBora;
                        parts.shift();
                    }
                    else{
                        // 2️⃣ Runtime plugin resolution
                        const plugin = app.plugin(rootName);
                        if(plugin){
                            ctx = plugin;
                            parts.shift();
                        }
                    }

                    if(!ctx){
                        if(dev){
                            console.warn(`[BoraEvents Strict] Blocked call to "${fn}"`);
                        }
                        return;
                    }

                    // Traverse remaining properties
                    while(parts.length > 1){
                        ctx = ctx[parts.shift()];
                        if(!ctx){
                            if(dev){
                                console.warn(`[BoraEvents Strict] Invalid path in "${fn}"`);
                            }
                            return;
                        }
                    }

                    const method = ctx[parts.shift()];

                    if(typeof method === 'function'){
                        method.apply(ctx, args.length ? args : [e, $el, eventType]);
                    }
                    else if(dev){
                        console.warn(`[BoraEvents Strict] Method not found: ${fn}`);
                    }

                    return;
                }

                /* =================================================
                LOOSE MODE (Legacy)
                ================================================= */

                const fnParts = fn.split('.');
                let ctx = window;

                for(let i = 0; i < fnParts.length - 1; i++){
                    ctx = ctx[fnParts[i]];
                    if(!ctx){
                        throw new Error(`Context not found: ${fnParts.slice(0, i+1).join('.')}`);
                    }
                }

                const method = ctx[fnParts.pop()];

                if(typeof method === 'function'){
                    method.apply(ctx, args.length ? args : [e, $el, eventType]);
                }
                else{
                    console.warn(`Function not found: ${fn}`);
                }

            }
            catch(err){
                console.error('Error executing data-e function:', err);
            }
        },

        resolveArg(rawArg, $el){

            if(!rawArg) return null;

            if(/^['"].*['"]$/.test(rawArg)){
                return rawArg.replace(/^['"]|['"]$/g, '');
            }

            if(!isNaN(rawArg)) return Number(rawArg);

            if(rawArg.startsWith('${') && rawArg.endsWith('}')){

                const key = rawArg.slice(2, -1).trim();

                if(key === 'val') return $el.val();
                if(key === 'text') return $el.text();
                if(key === 'html') return $el.html();

                if(key.startsWith('attr.')) return $el.attr(key.replace('attr.', ''));
                if(key.startsWith('data.')) return $el.data(key.replace('data.', ''));
                if(key.startsWith('prop.')) return $el.prop(key.replace('prop.', ''));

                return $el.attr(key) || $el.data(key) || null;
            }

            return rawArg;
        },

        resolveTrigger(trigger, e, $el, eventType){

            if(!hooks){
                console.warn('Hooks service not available.');
                return;
            }

            if(hooks.has(trigger)){
                hooks.call(trigger, { e, $el, eventType });
            }
            else{
                if(config.dev){
                    console.warn(`Trigger "${trigger}" not registered.`);
                }
            }
        },

        triggerCustom($target, name='custom', data={}){
            $target.trigger(name, data);
        }
    };

    /* -----------------------------------------
       jQuery extension preserved
    ----------------------------------------- */

    if(!$.fn.center){
        $.fn.center = function(){
            this.css("position", "fixed");
            this.css("top", ($(window).height() - this.outerHeight()) / 2 + "px");
            this.css("left", ($(window).width() - this.outerWidth()) / 2 + "px");
            return this;
        };
    }

    return BoraEvents;
});