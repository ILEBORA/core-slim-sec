__BORA_REGISTER_PLUGIN__('LogoutUX', function(scope){

    const hooks   = scope.getService('hooks');
    const alerts  = scope.plugin('alerts');
    const overlay = scope.plugin('Overlay');

    function init(){

        hooks.add('user.logout.request', async () => {

            try{
                await alerts.confirm('Are you <em>really</em> sure?', {
                    html: true
                }).autoCancel(10);

                overlay?.show('Logging out...');
                localStorage.removeItem("auth.token");

                return true;
            }
            catch(e){
                // user cancelled
                return false;
            }
        });
    }

    return { init };
});