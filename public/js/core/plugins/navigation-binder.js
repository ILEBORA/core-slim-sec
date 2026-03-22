__BORA_REGISTER_PLUGIN__('NavigationBinder', async function(scope){

    const navigation = await scope.getService('navigation');

    function bind(){
        $(document).on('click', 'a.jx', function(e){

            const href = $(this).attr('href');

            if(!href) return;
            if(href.startsWith('http')) return;
            if(href.startsWith('#')) return;
            if(href.endsWith('.pdf')) return;

            e.preventDefault();

            navigation.go(href);
        });
    }

    return {
        mount(){
            bind();
            console.log('[NavigationBinder] mounted');
        }
    };
});