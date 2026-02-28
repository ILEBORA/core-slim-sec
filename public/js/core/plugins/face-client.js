__BORA_REGISTER_PLUGIN__(
    'ClientFace',
    function(scope){

        const layouts = scope.getPlugin('Layouts');
        const navigation = scope.getService('navigation');

        return { mount, unmount };

        function mountO(){

            layouts?.mount();

            // Client-specific bindings
            navigation.go(window.location.pathname);
        }

        return { mount };
    },
    {
        requires:['Layouts','navigation']
    }
);