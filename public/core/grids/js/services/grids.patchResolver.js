__BORA_REGISTER_SERVICE__(

    'grids.patchResolver',

    async function(scope){

        /* =====================================================
         | Resolve target
         |===================================================== */

        function target(selector){

            return document.querySelector(
                selector
            );
        }

        /* =====================================================
         | Apply single patch
         |===================================================== */

        function applyPatch(patch = {}){

            const el =
                target(patch.target);

            if(!el){
                return;
            }

            switch(patch.mode){

                case 'append':

                    el.insertAdjacentHTML(
                        'beforeend',
                        patch.html || ''
                    );

                    break;

                case 'prepend':

                    el.insertAdjacentHTML(
                        'afterbegin',
                        patch.html || ''
                    );

                    break;

                case 'replace':

                    el.innerHTML =
                        patch.html || '';

                    break;

                case 'remove':

                    el.remove();

                    break;

                case 'text':

                    el.textContent =
                        patch.text || '';

                    break;
            }
        }

        /* =====================================================
         | Apply multiple patches
         |===================================================== */

        function apply(
            patches = []
        ){

            patches.forEach(
                applyPatch
            );
        }

        return {

            apply,
            applyPatch
        };
    }
);