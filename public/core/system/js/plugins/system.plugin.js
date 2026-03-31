__BORA_REGISTER_PLUGIN__(
'system.plugin',
async function(scope){

    let mounted = false;

    function mount(){

        if(mounted) return;
        mounted = true;
        alert('System mounted');

        console.log('[System] mounted');
    }

    function unmount(){

        if(!mounted) return;
        mounted = false;

       
        console.log('[System] unmounted');
    }

    //


    return { mount, unmount };

},
{

    requires:['realtime'],//,'hooks','events'],
    activateOn:(route)=> route.startsWith('bo')
    //TODO:: runtime face mount
    // faces: ['client', 'admin']
});