// config.js
export const GridsConfig = {
    api: null,

    init(runtime = {}) {
        this.api = runtime.api ?? window.RUNTIME?.api;
    }
};
