__BORA_REGISTER_SERVICE__('router', function(scope){

    const guards = [];

    function beforeEach(fn){
        guards.push(fn);
    }

    async function runGuards(to, from){

        for(const guard of guards){

            try{
                const result = await guard(to, from);

                if(result === false){
                    return { allow:false };
                }

                if(result && result.redirect){
                    return { allow:false, redirect:result.redirect };
                }

            }catch(err){
                console.error('[Router Guard Error]', err);
                return { allow:false };
            }
        }

        return { allow:true };
    }

    return {
        beforeEach,
        runGuards
    };
});