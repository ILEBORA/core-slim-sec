__BORA_REGISTER_PLUGIN__(
    'menu.resources',
    async function(scope){

        const resources =
            await scope.getService('resources');

        const callbora =
            await scope.getService('callbora');

        resources.register(
            'menus',
            async (role) => {

                role = role === 'admin' ? 'Administrator' : role;
                role = role === 'client' ? 'Client' : role;
                role = role === 'guest' ? 'Guest' : role;

                const res =
                    await callbora.get(
                        `api/modules/ui/menus/load/${role}/sidebar/true`
                    );

                return res;
            }
        );

    }
);