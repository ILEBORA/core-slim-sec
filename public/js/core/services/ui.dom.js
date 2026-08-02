__BORA_REGISTER_SERVICE__(
    'ui.dom',

    async function(scope){

        const registries = [];

        let observer = null;
        let observing = false;

        /*
        |--------------------------------------------------------------------------
        | Register
        |--------------------------------------------------------------------------
        */

        function register(config){

            registries.push({

                priority: 0,

                ...config

            });

            registries.sort(
                (a,b)=>
                    b.priority-a.priority
            );

            return this;
        }

        /*
        |--------------------------------------------------------------------------
        | Compile
        |--------------------------------------------------------------------------
        */

        function compile(root=document){

            if(!root){
                return;
            }

            registries.forEach(reg => {

                if(
                    root.matches &&
                    root.matches(
                        reg.selector
                    )
                ){

                    reg.mount?.(
                        root
                    );

                }

                root
                    .querySelectorAll?.(
                        reg.selector
                    )
                    .forEach(el => {

                        reg.mount?.(
                            el
                        );

                    });

            });

        }

        /*
        |--------------------------------------------------------------------------
        | Destroy
        |--------------------------------------------------------------------------
        */

        function destroy(root=document){

            if(!root){
                return;
            }

            registries.forEach(reg => {

                if(
                    root.matches &&
                    root.matches(
                        reg.selector
                    )
                ){

                    reg.destroy?.(
                        root
                    );

                }

                root
                    .querySelectorAll?.(
                        reg.selector
                    )
                    .forEach(el => {

                        reg.destroy?.(
                            el
                        );

                    });

            });

        }

        /*
        |--------------------------------------------------------------------------
        | Mutation Observer
        |--------------------------------------------------------------------------
        */

        function handleMutations(
            mutations
        ){
            // console.log('[MUTATIONS] handle...');
            mutations.forEach(mutation => {

                mutation
                    .addedNodes
                    .forEach(node => {

                        if(
                            node.nodeType !== 1
                        ){
                            return;
                        }

                        compile(
                            node
                        );

                    });

                mutation
                    .removedNodes
                    .forEach(node => {

                        if(
                            node.nodeType !== 1
                        ){
                            return;
                        }

                        destroy(
                            node
                        );

                    });

            });

        }

        /*
        |--------------------------------------------------------------------------
        | Observe
        |--------------------------------------------------------------------------
        */

        function observe(root=document.body){

            if(observing){
                return;
            }

            observer =
                new MutationObserver(
                    handleMutations
                );

            observer.observe(

                root,

                {

                    childList:true,

                    subtree:true

                }

            );

            observing = true;

            compile(root);
        }

        /*
        |--------------------------------------------------------------------------
        | Disconnect
        |--------------------------------------------------------------------------
        */

        function disconnect(){

            if(!observer){
                return;
            }

            observer.disconnect();

            observer = null;

            observing = false;

        }

        /*
        |--------------------------------------------------------------------------
        | Pause
        |--------------------------------------------------------------------------
        */

        function pause(){

            disconnect();

        }

        /*
        |--------------------------------------------------------------------------
        | Resume
        |--------------------------------------------------------------------------
        */

        function resume(root=document.body){

            observe(root);

        }

        /*
        |--------------------------------------------------------------------------
        | Refresh
        |--------------------------------------------------------------------------
        */

        function refresh(root=document){

            destroy(root);

            compile(root);

        }

        /*
        |--------------------------------------------------------------------------
        | Start Automatically
        |--------------------------------------------------------------------------
        */

        if(
            document.readyState ===
            'loading'
        ){

            document.addEventListener(

                'DOMContentLoaded',

                ()=>observe()

            );

        }else{

            observe();

        }

        /*
        |--------------------------------------------------------------------------
        | API
        |--------------------------------------------------------------------------
        */

        return {

            register,

            compile,

            destroy,

            refresh,

            observe,

            disconnect,

            pause,

            resume

        };

    }

);