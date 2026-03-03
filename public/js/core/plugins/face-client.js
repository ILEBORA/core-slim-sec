__BORA_REGISTER_PLUGIN__(
    'ClientFace',
    function(scope){

        const layouts = scope.getPlugin('Layouts');

        function mount(){

            layouts?.mount();

            console.log('[ClientFace] mounted');
        }

        return { mount };
    },
    {
        requires:['Layouts']
    }
);