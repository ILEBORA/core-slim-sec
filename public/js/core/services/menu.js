__BORA_REGISTER_SERVICE__(
    'menu',
    async function(scope){

        const hooks = await scope.getService('hooks');
        const navigation = await scope.getService('navigation');
        const resources = await scope.getService('resources');

        let currentRole = null;
        let loadingRole = null;

        async function refresh(role, options = {}){
            // alert(role);
            role = role == 'admin' ? 'Administrator' : role;
            role = role == 'client' ? 'Client' : role;
            role = role == 'guest' ? 'Guest' : role;

            const {
                force = false
            } = options;

            if(!role){
                return;
            }

            // already active
            if(!force && currentRole === role){

                console.log(
                    `[Menu] Skipping refresh. Already "${role}"`
                );

                return;
            }

            // already loading same role
            if(loadingRole === role){

                console.log(
                    `[Menu] "${role}" already loading`
                );

                return;
            }

            const container =
                document.querySelector('.features-list');

            if(!container){
                return;
            }

            loadingRole = role;

            container.innerHTML =
                "<center><img src='assets/images/icons/ajax.gif'></center>";

             const data =
                await resources.get(
                    'menus',
                    role
                );

            console.log('[Response]',data);

            if(data.success){

                container.innerHTML =
                    data.html;

                currentRole =
                    role;

                hooks.call?.(
                    'page.loaded',
                    window.location.href
                );

                navigation.highlight();
            }

            // try {

            //     const response = await fetch(
            //         `api/modules/ui/menus/load/${role}/sidebar/true`,
            //         {
            //             headers: {
            //                 'X-Requested-With':'XMLHttpRequest'
            //             }
            //         }
            //     );

            //     const data = await response.json();

            //     if(data.success){

            //         container.innerHTML = data.html;

            //         currentRole = role;

            //         hooks?.call?.(
            //             'page.loaded',
            //             window.location.href
            //         );

            //         navigation.highlight?.();

            //         console.log(
            //             `[Menu] Loaded "${role}" menu`
            //         );
            //     }

            // } catch(err){

            //     console.error('[Menu refresh error]', err);

            // } finally {

            //     loadingRole = null;

            // }
        }

        async function refreshO2(role, options = {}){
            role = role == 'admin' ? 'Administrator' : role;
            role = role == 'client' ? 'Client' : role;
            role = role == 'guest' ? 'Guest' : role;

            const {
                force = false
            } = options;

            if(!role){
                return;
            }

            // already active
            if(!force && currentRole === role){

                console.log(
                    `[Menu] Skipping refresh. Already "${role}"`
                );

                return;
            }

            // already loading same role
            if(loadingRole === role){

                console.log(
                    `[Menu] "${role}" already loading`
                );

                return;
            }

            const container =
                document.querySelector('.features-list');

            if(!container){
                return;
            }

            loadingRole = role;

            container.innerHTML =
                "<center><img src='assets/images/icons/ajax.gif'></center>";

            try {

                const response = await fetch(
                    `api/modules/ui/menus/load/${role}/sidebar/true`,
                    {
                        headers: {
                            'X-Requested-With':'XMLHttpRequest'
                        }
                    }
                );

                const data = await response.json();

                if(data.success){

                    container.innerHTML = data.html;

                    currentRole = role;

                    hooks?.call?.(
                        'page.loaded',
                        window.location.href
                    );

                    navigation.highlight?.();

                    console.log(
                        `[Menu] Loaded "${role}" menu`
                    );
                }

            } catch(err){

                console.error('[Menu refresh error]', err);

            } finally {

                loadingRole = null;

            }
        }

        function current(){
            return currentRole;
        }

        // React to context changes automatically
        // scope.on?.('face.changed', (face) => {
        //     alert('here face-changed');
        //     refresh(face);
        //     navigation.highlight();
        // });

        return { refresh, current };
    }
);