__BORA_REGISTER_PLUGIN__(
'face.client',
async function(scope){

    const layouts = await scope.getPlugin('layouts');

    const state = { 
        mounted: false
    };

    function mount(){
        if (state.mounted) return;
        state.mounted = true;

        layouts?.mount();

        // alert('Welcome to the Client Face!');

        console.log('[Client Face] mounted');
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
    faces: ['client']
}
);