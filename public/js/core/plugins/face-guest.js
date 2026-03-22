__BORA_REGISTER_PLUGIN__(
    'GuestFace',
    async function(scope){

        const layouts = await scope.getPlugin('Layouts');

        function mount(){
            layouts?.mount();
            console.log('[GuestFace] mounted');
        }

        function unmount(){
            layouts?.unmount();
        }

        return { mount, unmount };
    },
    {
        requires:['Layouts'],
        faces: ['guest']
    }
);