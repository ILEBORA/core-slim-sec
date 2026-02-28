__BORA_REGISTER_PLUGIN__(
    'GuestFace',
    function(scope){

        const layouts = scope.getPlugin('Layouts');

        function mount(){
            layouts?.mount();
        }

        function unmount(){
            layouts?.unmount();
        }

        return { mount, unmount };
    },
    {
        requires:['Layouts']
    }
);