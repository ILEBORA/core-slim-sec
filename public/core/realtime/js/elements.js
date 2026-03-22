// Bora Live UI 4
class BoraLvui extends HTMLElement {
    constructor() {
        super();
        // this.attachShadow({ mode: 'open' });
    }

    connectedCallback() {
        this.render();
        this.initialize();
        // this.addToLive();
    }

    render() {
        const initialValue = this.getAttribute("value") || "";
        this.innerHTML = `${initialValue}`;
        // this.shadowRoot.innerHTML = `${initialValue}`;
    }

    initialize() {
        const tag = this.getAttribute('blvui');
        this.setAttribute('data-blvui', tag);

        if (!UI.update[tag]) {
            this.addToLive();
        }
    }

    addToLive() {
        const tag = this.getAttribute("blvui");

        if (!UI.update.hasOwnProperty(tag)) {
            // console.warn('SSE::',1);
            this.addToCookies();

            UI.update[tag] = ((el) => {
                return {
                    set val(v) {
						if (typeof v === 'object' && v !== null && !Array.isArray(v)) {
							// el.shadowRoot.querySelector('span').textContent = '';
							$(`[blvui=${tag}]`).data('obj', v);
						} else if (typeof v === 'string' || typeof v === 'number') {
							// el.shadowRoot.querySelector('span').textContent = v;
							$(`[blvui=${tag}]`).html(v);
						}

                         // 🔥 Always trigger change automatically
                        $(`[blvui=${tag}]`).trigger('change');
                    },
                    get val() {
                        return el.textContent;
                    }
                };
            })(this);
        }
    }

    async addToCookies() {
        const tag = this.getAttribute("blvui");
        if(tag){
            const call = await __BORA_APP__?.service('callbora');
            if(call){
                call.post(
                    `api/modules/realtime/tags/add`,
                    {tag: tag }
                );
            }
            // new CallBora(`api/modules/realtime/tags/add`)
            //     .setMethod("POST")
            //     .setParams({tag: tag })
            //     .setCallback((data) => {
            //         // console.log(data.html);
            //         if(data.success){
            //             //TODO:: Decide what to do with feedback data
            //         }
            //     })
            //     .setDone(() => {
            //         console.log("Request finished");
            //         //Hide Overlay
            //     })
            //     .setError((xhr) => {
            //         console.error("Error:", xhr);
            //     })
            //     .build();
        }
    }
}

// Register the custom element
customElements.define('bora-lvui', BoraLvui);

// const FactBusX = await __BORA_APP__.service('factbus');

const FactBusO = (function () {
    const handlers = {};

    function on(type, fn) {
        if (!handlers[type]) handlers[type] = [];
        handlers[type].push(fn);
    }

    function dispatch(fact, meta = {}) {
        const type = fact.type;
        const fns = [
            ...(handlers['*'] || []),
            ...(handlers[type] || [])
        ];

        if (!fns.length) return;

        fns.forEach(fn => {
            try {
                fn(fact, meta);
            } catch (e) {
                console.error('Fact handler failed:', type, e);
            }
        });
    }

    return { on, dispatch };
})();