__BORA_REGISTER_PLUGIN__('logout.ux', async function(scope){

    const hooks   = await scope.getService('hooks');
    const alerts  = await scope.getPlugin('alerts');
    const overlay = await scope.getPlugin('overlay');

    const   state = {       
        mounted: false
    };

    function mount(){ 
        if (state.mounted) return;
        state.mounted = true;

        console.log('[logout.ux] mounted');
        hooks.add('user.logout.request', async () => {

            return alerts.confirm('Are you <em>really</em> sure?', {
                html: true
            }).autoCancel(20)
            .then(() => {
                overlay?.show('Logging out...');
                localStorage.removeItem("auth.token");
                return true;
            })
            .catch(() => {
                console.log('Confirmation canceled');
                return false;
            });
        });
    }

    function unmount(){
        if (!state.mounted) return; //FIXED (was wrong)
        state.mounted = false;  
    }

    return { mount, unmount };
},{
    requires: ['hooks', 'alerts', 'overlay', 'layout.sidebar']
});