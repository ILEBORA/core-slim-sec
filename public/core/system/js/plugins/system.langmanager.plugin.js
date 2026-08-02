__BORA_REGISTER_PLUGIN__(
'system.langmanager.plugin',
async function(scope){

    const navigation = await scope.getService('navigation');
    const uiActions = await scope.getService('ui.actions');

    const state = {
        mounted: false
    };

    function mount(){
        if (state.mounted) return;
        state.mounted = true;
        // alert('System mounted');

        console.log('[System] system.langmanager.plugin mounted');

        $(function(){
            uiBind();
        });
    }

    function unmount(){
        if (!state.mounted) return;
        state.mounted = false;  

        console.log('[System] system.langmanager.plugin unmounted');
    }
    //

    function uiBind(){

        uiActions.register('system:load.translations',function(){
            const module = $('#moduleSelect').val();
            const lang   = $('#langSelect').val();

            navigation.go(`bo/system/langmanager/${module}/${lang}`);
        });

        uiActions.register('system:save.translations', function(){

            const formData = $('#translationsForm').serialize();
            const module = $('#moduleSelect').val();
            const lang   = $('#langSelect').val();

            $.post(`api/modules/system/langmanager/save/${module}/${lang}`, formData, function(res){
                if(res.success){
                    alertBora.notify('Translations saved', 'success');
                } else {
                    alertBora.notify(res.message ?? 'Error', 'error');
                }
            });

        });


        uiActions.register('system:sync.translations', function(){

            const module = $('#moduleSelect').val();
            const lang   = $('#langSelect').val();

            alertBora.confirm('Sync missing keys from JSON?', { html:true })
            .then(function(){

                $.post(`api/modules/system/langmanager/sync/${module}/${lang}`, function(res){
                    if(res.success){
                        alertBora.notify('Synced successfully', 'success');
                        location.reload();
                    } else {
                        alertBora.notify(res.message ?? 'Error', 'error');
                    }
                });

            });

        });


        $('#search').on('keyup', function(){
            const term = $(this).val().toLowerCase();

            $('#translationsTable tr').each(function(){
                const key = $(this).find('td:first').text().toLowerCase();
                $(this).toggle(key.includes(term));
            });
        });

        //
        $('#loadModule').on('click', function(){
            const module = $('#moduleSelect').val();
            window.location.href = `bo/system/langmanager/missing/${module}`;
        });

        $('#addAllMissing').on('click', function(e){
            e.preventDefault();

            const data = $('#missingForm').serialize();
            const module = $('#moduleSelect').val();

            $.post(`api/modules/system/langmanager/save/${module}/en`, data, function(res){
                if(res.success){
                    alertBora.notify('Added to EN', 'success');
                    location.reload();
                } else {
                    alertBora.notify(res.message ?? 'Error', 'error');
                }
            });
        });

    }


    return { mount, unmount };

},
{

    requires:[],//['realtime'],//,'hooks','events'],
    activateOn:(route)=> route.startsWith('bo/system/langmanager')
    //TODO:: runtime face mount
    // faces: ['client', 'admin']
});