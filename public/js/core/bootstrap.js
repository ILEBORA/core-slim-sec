(function(global){

    const config = global.__BORA_CONFIG__ || {};

    const app = BoraRuntime(config);
    global.__BORA_APP__ = app;

    app.start();

    // Remove build-time registration surface
    delete global.__BORA_REGISTER_PLUGIN__;
    delete global.__BORA_REGISTER_SERVICE__;

    /* ------------------------------------
       Backward Compatibility Layer
    ------------------------------------ */

    const alerts = app.plugin('BoraAlertsV2');

    if (alerts) {

        // v2 explicit alias
        global.alertBoraV2 = alerts;

        // legacy alias (only if not already defined)
        if (!global.alertBora) {
            global.alertBora = alerts;
        }
    }

})(window);