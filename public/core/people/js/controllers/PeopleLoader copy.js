class PeopleLoader {

    constructor(scope, callbora, ui) {
        this.scope    = scope;
        this.callbora = callbora;
        this.ui       = ui;

        this.cache = new Map(); // 🔥 critical
    }

    async loadPerson(personId) {
        // ✅ cache first
        if (this.cache.has(personId)) {
            return this.cache.get(personId);
        }

        const res = await this.callbora.get(`api/modules/people/person/${personId}`);

        if (!res || !res.data) return null;

        const person = this.normalize(res.data);

        this.cache.set(personId, person);

        return person;
    }

    async loadBatch(ids = []) {
        const missing = ids.filter(id => !this.cache.has(id));

        if (missing.length) {
            const res = await this.callbora.post(`api/modules/people/batch`, { ids });

            (res.data || []).forEach(p => {
                const person = this.normalize(p);
                this.cache.set(person.id, person);
            });
        }

        return ids.map(id => this.cache.get(id)).filter(Boolean);
    }

    normalize(person) {
        return {
            ...person,
            user: person.user || null
        };
    }

    async resolvePersonFromRoute() {
        const match = location.pathname.match(/people\/(\d+)/);
        if (!match) return;

        const personId = parseInt(match[1], 10);

        const person = await this.loadPerson(personId);

        if (person) {
            // this.ui.renderPersonCard(person);
            this.scope.emit('people.loaded', { person });
        }
    }
}