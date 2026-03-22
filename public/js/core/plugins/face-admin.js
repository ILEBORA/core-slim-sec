__BORA_REGISTER_PLUGIN__(
    'AdminFace',
    async function(scope){

        const layouts = await scope.getPlugin('Layouts');

        function mount(){

            layouts?.mount();

            console.log('[AdminFace] mounted');
        }

        function unmount(){
            layouts?.unmount?.();
        }

        return { mount, unmount };
    },
    {
        requires:['Layouts'],
        faces: ['admin']
    }
);