__BORA_REGISTER_PLUGIN__(
    'ClientFace',
    async function(scope){

        const layouts = await scope.getPlugin('Layouts');

        function mount(){

            layouts?.mount();

            console.log('[ClientFace] mounted');
        }

        function unmount(){
            layouts?.unmount?.();
        }

        return { mount, unmount };
    },
    {
        requires:['Layouts'],
        faces: ['client']
    }
);