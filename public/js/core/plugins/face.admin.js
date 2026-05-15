__BORA_REGISTER_PLUGIN__(
    'face.admin',
    async function(scope){

        const layouts = await scope.getPlugin('layouts');

        const state = {
            mounted: false
        };

        function mount(){
            if (state.mounted) return;
            state.mounted = true;

            layouts?.mount();

            // alert('Welcome to the Admin Face!');

            console.log('[Admin Face] mounted');
        }

        function unmount(){
            if (!state.mounted) return;
            state.mounted = false;  
            
            layouts?.unmount?.();
        }

        return { mount, unmount };
    },
    {
        requires:['layouts'],
        faces: ['admin']
    }
);