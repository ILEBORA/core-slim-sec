__BORA_REGISTER_SERVICE__(
    'menu',
    async function(scope){

        const hooks = await scope.getService('hooks');
        const navigation = await scope.getService('navigation');

        async function refresh(role){

            const container = document.querySelector('.features-list');
            if (!container) return;

            container.innerHTML =
                "<center><img src='assets/images/icons/ajax.gif'></center>";

            try {

                const response = await fetch(
                    `api/modules/ui/menus/load/${role}/sidebar/true`,
                    { headers: { 'X-Requested-With':'XMLHttpRequest' } }
                );

                const data = await response.json();

                if (data.success){
                    container.innerHTML = data.html;

                    // re-activate route
                    hooks?.call?.('page.loaded', window.location.href);

                }

            } catch (err){
                console.error('[Menu refresh error]', err);
            }
        }

        // React to context changes automatically
        scope.on?.('context.changed', (face) => {
            refresh(face);
            navigation.highlight();
        });

        return { refresh };
    }
);