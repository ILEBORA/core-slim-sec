class PeopleLoader {

    constructor(scope, callbora) {
        this.scope    = scope;
        this.callbora = callbora;

        // cache HTML views
        this.viewCache = new Map();   // personId → HTML
        this.tabCache  = new Map();   // personId:tab → HTML

        // inflight requests
        this.inflight = new Map();
    }

    /* ========================================
     * PERSON VIEW (HTML)
     * ====================================== */

    async loadPersonView(personId) {

        // cache hit
        if (this.viewCache.has(personId)) {
            return this.viewCache.get(personId);
        }

        const key = `view:${personId}`;

        if (this.inflight.has(key)) {
            history.pushState({}, '', `portal/people/person/${personId}/view`);
            return this.inflight.get(key);
        }

        const promise = this.callbora
            .get(`api/modules/people/person/${personId}/info`)
            .then(html => {
                this.viewCache.set(personId, html);
                this.inflight.delete(key);
                history.pushState({}, '', `portal/people/person/${personId}/view`);
                return html;
            })
            .catch(err => {
                this.inflight.delete(key);
                throw err;
            });

        this.inflight.set(key, promise);

        return promise;
    }

    /* ========================================
     * TAB CONTENT (HTML)
     * ====================================== */

    async getTabContent(personId, tab) {

        const cacheKey = `${personId}:${tab}`;

        if (this.tabCache.has(cacheKey)) {
            return this.tabCache.get(cacheKey);
        }

        const key = `tab:${cacheKey}`;

        if (this.inflight.has(key)) {
            return this.inflight.get(key);
        }

        const promise = this.callbora
            .get(`api/modules/people/person/${personId}/tabs/${tab}`)
            .then(response => {

                let parsed = null;

                if (typeof response === 'object' && response !== null) {
                    parsed = response;
                } else if (typeof response === 'string') {
                    try {
                        parsed = JSON.parse(response);
                    } catch (e) {
                        parsed = null;
                    }
                }

                if (parsed && typeof parsed === 'object') {
                    // 🚨 JSON response → error case
                    if (parsed.success === false) {
                        const html = `
                            <div class="error unauthorized">
                                <strong>${parsed.message || 'Error'}</strong>
                            </div>
                        `;

                        // ✅ assume HTML
                        this.tabCache.set(cacheKey, html);
                        this.inflight.delete(key);

                        return html;
                    }
                }

                // ✅ assume HTML
                this.tabCache.set(cacheKey, response);
                this.inflight.delete(key);

                return response;
            })
            .catch(err => {
                this.inflight.delete(key);
                throw err;
            });

        // const promise = this.callbora
        //     .get(`api/modules/people/person/${personId}/tabs/${tab}`)
        //     .then(html => {
        //         this.tabCache.set(cacheKey, html);
        //         this.inflight.delete(key);
                
        //         return html;
        //     })
        //     .catch(err => {
        //         this.inflight.delete(key);
        //         throw err;
        //     });

        this.inflight.set(key, promise);

        return promise;
    }

    /* ========================================
     * ROUTE RESOLUTION (OPTIONAL)
     * ====================================== */

    async resolvePersonFromRoute() {

        const match = location.pathname.match(/person\/(\d+)/);
        if (!match) return;

        const personId = parseInt(match[1], 10);

        this.scope.emit('people.person.open', {
            personId
        });
    }

    async getTree(personId, treeId) {
        return this.callbora.get(
            `api/modules/people/person/${personId}/tree/${treeId}`
        );
    }

    /* ========================================
     * CACHE CONTROL
     * ====================================== */

    invalidate(personId) {
        this.viewCache.delete(personId);

        // remove related tabs
        [...this.tabCache.keys()].forEach(key => {
            if (key.startsWith(`${personId}:`)) {
                this.tabCache.delete(key);
            }
        });
    }

    invalidateAll() {
        this.viewCache.clear();
        this.tabCache.clear();
    }
}