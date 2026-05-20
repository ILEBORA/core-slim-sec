__BORA_REGISTER_PLUGIN__(
'people.breadcrumbs',
async function(scope){

    // const hooks = await scope.getService('hooks');
    const breadcrumbs = await scope.getService('breadcrumbs');

    function mount(){
        // alert('people.breadcrumbs');
        scope.on('breadcrumbs:resolve', async ({ url, response }) => {
            
            if (!url?.startsWith('portal/people/person/')) return;
            // alert('bcrumb here '+ url);
            const person = response?.data?.person;
            if (!person){
                breadcrumbs.set([
                    { label: 'People', href: 'portal/people' },
                    { label: 'Person', current: true }
                ]);
                return;
            }
            // alert('person found');
            breadcrumbs.set([
                { label: 'People', href: 'portal/people' },
                { label: person.full_name, current: true }
            ]);
        });
    }

    function unmount(){
        scope.off('breadcrumbs:resolve');
    }

    return { mount, unmount };
},{
    requires:['realtime'],
    activateOn: (route) => route.startsWith('portal/people')
});