__BORA_REGISTER_SERVICE__('pipeline', function(scope){

    async function getProcessors(type){

        const plugins = await scope.getPluginsByPrefix(`pipeline.${type}`).catch(() => []);

        // return plugins
        //     .filter(p => typeof p.process === 'function')
        //     .sort((a, b) => (a.priority || 100) - (b.priority || 100));

        return plugins
            .sort((a, b) => (a.meta.priority || 100) - (b.meta.priority || 100))
            .map(p => p.instance);
    }

    async function run(type, input){

        let ctx = createContext(input);

        const processors = await getProcessors(type);

        for (let p of processors){

            const result = await p.process(ctx);

            if(result === null){
                ctx.aborted = true;
                return null;
            }

            // allow processor to replace ctx or mutate
            if(result) ctx = result;
        }

        return ctx;
    }

    return { run };
});