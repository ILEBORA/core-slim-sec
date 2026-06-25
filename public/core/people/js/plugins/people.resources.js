__BORA_REGISTER_PLUGIN__(
    'people.resources',
    async function(scope){

        const resources =
            await scope.getService(
                'resources'
            );

        const callbora =
            await scope.getService(
                'callbora'
            );

        resources.register(
            'people',
            async () => {

                const res =
                    await callbora.get(
                        'api/modules/people/dictionary'
                    );

                return res.data;
            }
        );
    }
);