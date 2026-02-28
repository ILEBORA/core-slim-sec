__BORA_REGISTER_PLUGIN__(
    'AdminFace',
    function(scope){

        const layouts = scope.getPlugin('Layouts');

        function mount(){

            layouts?.mount();

            console.log('[AdminFace] mounted');
        }

        return { mount };
    },
    {
        requires:['Layouts']
    }
);