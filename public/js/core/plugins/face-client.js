__BORA_REGISTER_PLUGIN__(
'ClientFace',
async function(scope){

    const layouts = await scope.getPlugin('Layouts');

    const state = { 
        mounted: false
    };

    function mount(){
        if (state.mounted) return;
        state.mounted = true;

        layouts?.mount();

        console.log('[ClientFace] mounted');
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
    faces: ['client']
}
);