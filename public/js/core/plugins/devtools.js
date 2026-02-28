__BORA_REGISTER_PLUGIN__(
    'DevTools',
    function(scope){

        const config   = scope.config || {};
        const devtools = scope.getService('devtools');

        function mount(){

            if(!config.dev) return;

            globalThis.__BORA_DEV__ = devtools;

            console.log(
                '%c Bora DevTools Ready',
                'color:#8b5cf6;font-weight:bold;'
            );
        }

        return { mount };
    },
    {
        requires:['devtools']
    }
);