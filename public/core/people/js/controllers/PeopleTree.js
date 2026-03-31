class PeopleTree {

    constructor(loader) {
        this.loader = loader;
    }

    async getChildren(personId) {
        const res = await fetch(`/tree/${personId}/children`);
        const data = await res.json();

        return this.loader.loadBatch(data.ids);
    }

    async getParents(personId) {
        const res = await fetch(`/tree/${personId}/parents`);
        const data = await res.json();

        return this.loader.loadBatch(data.ids);
    }
}