__BORA_REGISTER_PLUGIN__(
'dashboards.controller',
async function(scope){

    const uiActions = await scope.getService('ui.actions');
    const workspace = await scope.getPlugin('dashboards.workspace');
    const notifications = await scope.getService('dashboards.notifications');
    const resources = await scope.getService('resources');

    function bind(){
        

    }

    async function mount(){

        bind();

    }

    return{

        mount

    };

});