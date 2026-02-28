(function(){

    const app = window.__BORA_APP__;

    if(!app){
        console.error('Bora runtime not found.');
        return;
    }

    /* ------------------------------------
       Optional: Dev Diagnostics
    ------------------------------------ */

    if(app.service('deprecations')){
        app.on('runtime:started', () => {
            console.log('%c Bora Client Loaded (Strict Mode)', 
                'color:#10b981;font-weight:bold;');
        });
    }

    /* ------------------------------------
       Nothing else here.
       All logic lives in runtime plugins.
    ------------------------------------ */

})();