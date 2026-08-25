__BORA_REGISTER_PLUGIN__(
'grid.actions',

async function(scope){

    const uiActions  = await scope.getService('ui.actions');
    const popup      = await scope.getPlugin('popup');
    const callbora   = await scope.getService('callbora');
    const navigation = await scope.getService('navigation');
    const bNavigator = await scope.getService('navigator');

    const uiBindings = await  scope.getPlugin('ui.bindings');
    const appState = await scope.getService('state');
    const resources = await scope.getService('resources');
    

    const state = {
        initialized:false,
        mounted:false
    };

    // async function ensureController(){

    //     return await scope.getPlugin(
    //         'people.controller'
    //     );

    // }

    function openPersonEdit(personId){

        popup.open({
            mode:'form',
            module:'people',
            group:'person',
            tab:'edit',
            view:'edit',
            id:personId,
            size:'md'
        });

    }

    
    function registerActions(){
        // alert('Grid actions');
        uiActions.register('grids.pagesize.change', (el) => {
            const obj = $(el);
            const gridId = obj.data('grid-id');
            const size = obj.val();

            console.log(obj.val());
            alert('here '+gridId);
            callbora.post(`api/modules/grids/change-page-size`, {
                id: gridId,
                size: size
            }).then(function(response){
                if(response.success){
                    alertBora.success(response.message || 'Succeeded');
    
                    
                } else {
                    alertBora.error(response.message || 'Failed');
                }
    
            });
    
        });

        uiActions.register('grids.column.settings', async (el) => {
            const bNavigator = await scope.getService('navigator');
            const gridId = $(el).data('grid');
    
            bNavigator.go({
    
                route:'grids.column.settings',
    
                params:{
                    id:gridId
                },
    
                surface:'popup'
    
            });
        });
        

        
        uiBindings.bind();

    }

    function init(){

        if(state.initialized){
            return;
        }

        state.initialized = true;

        registerActions();

    }

    function mount(){

        if(state.mounted){
            return;
        }
        // alert('Grid ACtions mounted');
        state.mounted = true;

        init();

    }

    function unmount(){

        if(!state.mounted){
            return;
        }
        // alert('People ACtions unmounted');
        state.mounted = false;

    }


    return {
        mount,
        unmount,
        init
    };
    
});