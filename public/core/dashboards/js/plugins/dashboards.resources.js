__BORA_REGISTER_PLUGIN__(

'dashboards.resources',

async function(scope){

    const resources = await scope.getService('resources');
    const appState = await scope.getService('state');
    const bindings = await scope.getPlugin( 'ui.bindings');
    const callbora = await scope.getService('callbora');

    /*
    |--------------------------------------------------------------------------
    | Checkout
    |--------------------------------------------------------------------------
    */

    const state = {
        initialized:false,
        mounted:false
    };

    function mount(){

        if(state.mounted){
            return;
        }
        // alert('dashboards. resources mounted');
        state.mounted = true;

        init();

    }

    function unmount(){

        if(!state.mounted){
            return;
        }
        // alert('dashboards. ACtions unmounted');
        state.mounted = false;

    }

    function init(){

        if(state.initialized){
            return;
        }

        state.initialized = true;

        registerListeners();

    }

    function registerListeners(){
        scope.on('view:mounted', ({ root }) => {
            bindings.mount(root);
        });

        scope.on('view:destroyed', ({ root }) => {
            bindings.destroy(root);
        });

        
    }

    return {
        mount,
        unmount
    };

});