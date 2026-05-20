__BORA_REGISTER_PLUGIN__(
    'entity.lifecycle',
    async function(scope){

    const callbora =
        await scope.getService(
            'callbora'
        );

    async function mutate({
        module,
        entity,
        id,
        action,
        passwordRequired = true,
        source = null
    }){

        let payload = {};

        /*
        |--------------------------------------------------------------------------
        | Password confirm
        |--------------------------------------------------------------------------
        */

        if(passwordRequired){

            const det =
                await alertBora.prompt(
                    '<h3>Confirm Action</h3>Enter your password to continue',
                    {
                        html: true,
                        prompt: `
                            <input
                                type="password"
                                name="password"
                                placeholder="Password"
                            >
                        `
                    }
                );

            if(!det?.password){
                return;
            }

            payload.password =
                btoa(det.password);
        }

        /*
        |--------------------------------------------------------------------------
        | Request
        |--------------------------------------------------------------------------
        */

        const response =
            await callbora.post(
                `api/modules/${module}/${entity}/${id}/${action}`,
                payload
            );

        /*
        |--------------------------------------------------------------------------
        | Failure
        |--------------------------------------------------------------------------
        */

        if(!response.success){

            alertBora.error(
                response.message || 'Failed'
            );

            return response;
        }

        /*
        |--------------------------------------------------------------------------
        | Success
        |--------------------------------------------------------------------------
        */

        alertBora.success(
            response.message || 'Success'
        );

        /*
        |--------------------------------------------------------------------------
        | Domain event
        |--------------------------------------------------------------------------
        */

        scope.emit(
            `${entity}.${action}`,
            {
                entity,
                action,

                data: {
                    id
                },

                response,

                source
            }
        );

        return response;
    }

    return {
        mutate
    };
});