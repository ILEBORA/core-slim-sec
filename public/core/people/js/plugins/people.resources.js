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

        /*
        |--------------------------------------------------------------------------
        | Person Added
        |--------------------------------------------------------------------------
        */

        scope.on(
            'people.added',

            ({
                person
            }) => {

                resources.patch(
                    'people',
                    null,

                    people => {

                        people.push({
                            id: person.id,
                            text: person.full_name
                        });

                        people.sort(
                            (a,b)=>
                                a.text.localeCompare(
                                    b.text
                                )
                        );

                        return {
                            data: people
                        };
                    }
                );

            }
        );

        /*
        |--------------------------------------------------------------------------
        | Person Updated
        |--------------------------------------------------------------------------
        */

        scope.on(
            'people.updated',

            ({
                person
            }) => {

                resources.patch(
                    'people',
                    null,

                    people => {

                        const p =
                            people.find(
                                x =>
                                    x.id ==
                                    person.id
                            );

                        if(p){
                            p.text =
                                person.full_name;
                        }

                        return {
                            data: people
                        };
                    }
                );

            }
        );

        /*
        |--------------------------------------------------------------------------
        | Person Deleted
        |--------------------------------------------------------------------------
        */

        scope.on(
            'people.deleted',

            ({
                personId
            }) => {

                resources.patch(
                    'people',
                    null,

                    people => {

                        return {
                            data:
                                people.filter(
                                    p =>
                                        p.id !=
                                        personId
                                )
                        };
                    }
                );

            }
        );
    }
);