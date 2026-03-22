__BORA_REGISTER_PLUGIN__('LogoutUX', async function(scope){

    const hooks   = await scope.getService('hooks');
    const alerts  = await scope.getPlugin('alerts');
    const overlay = await scope.getPlugin('Overlay');

    function mount(){ 
        console.log('[LogoutUX] mounted');
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

    return { mount };
});