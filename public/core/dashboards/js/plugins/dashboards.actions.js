__BORA_REGISTER_PLUGIN__(

'dashboards.actions',

async function(scope){

    const workspace     = await scope.getPlugin('billing.workspace');
    const uiActions     = await scope.getService('ui.actions');
    const bNavigator    = await scope.getService('navigator');
    const navigation    = await scope.getService('navigation');
    const lifecycle     = await scope.getPlugin('entity.lifecycle');
    const callbora      = await scope.getService('callbora');
    const alerts        = await scope.getPlugin('alerts');

    const state = {
        initialized:false,
        mounted:false
    };


    function mount(){
        if (state.mounted) return;
        state.mounted = true;
        // alert('dashboard.actions');
        init();
    }

    function unmount(){
        if (!state.mounted) return;
        state.mounted = false;
        state.initialized = false;
    }

    function init(){
        console.log('[BILLING ACTIONS]','state', state.initialized);
        if(state.initialized){
            return;
        }

        registerActions();

    }

    function registerActions(){

        uiActions.register('dashboard.toggle-controls',(el)=>{
            console.log('toggle controls');
            el.classList.toggle('opened');

            const container = el.closest('.dash-controls-container');
            if(!container) return;

            container.classList.toggle('expanded');

            const controls = container.querySelector('.dash-controls');
            if(controls) controls.classList.toggle('expanded');

            const icon = el.querySelector('i');
            if(icon){
                icon.classList.toggle                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                ('fa-cogs');
                icon.classList.toggle('fa-times');
            }
        });
        

    }

    async function openPaymentMethods(el){
        const key = $(el).attr('data-key');
        
        const bNavigator    = await scope.getService('navigator');

        bNavigator.go({

            route:'billing.payment.methods',

            params:{
                key:key
            },

            surface:'popup'

        });

        
    }

    

    return{
        mount,
        unmount,

    };

});