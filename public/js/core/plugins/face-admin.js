__BORA_REGISTER_PLUGIN__(
    'AdminFace',
    async function(scope){

        const layouts = await scope.getPlugin('Layouts');

        const state = {
            mounted: false
        };

        function mount(){
            if (state.mounted) return;
            state.mounted = true;

            layouts?.mount();

            console.log('[AdminFace] mounted');
        }

        function unmount(){
            if (!state.mounted) return;
            state.mounted = false;  
            
            layouts?.unmount?.();
        }

        return { mount, unmount };
    },
    {
        requires:['Layouts'],
        faces: ['admin']
    }
);