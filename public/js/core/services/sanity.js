__BORA_REGISTER_SERVICE__('sanity', function(scope){

    const config = scope.config || {};
    const issues = [];

    function checkService(name){
        if(!scope.getService(name)){
            issues.push(`Missing service: ${name}`);
        }
    }

    function checkPlugin(name){
        if(!scope.getPlugin || !scope.getPlugin(name)){
            issues.push(`Missing plugin: ${name}`);
        }
    }

    function checkLegacy(){
        if(config.securityMode === 'strict'){
            if(window.appHooks){
                issues.push('Legacy appHooks detected in strict mode.');
            }
        }
    }

    function run(){

        issues.length = 0;

        checkService('state');
        checkService('navigation');
        checkService('hooks');
        checkService('meta');

        checkPlugin('ContentManager');
        checkPlugin('NavigationBinder');

        checkLegacy();

        return {
            ok: issues.length === 0,
            issues: [...issues]
        };
    }

    return { run };
});