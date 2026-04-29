__BORA_REGISTER_PLUGIN__(
'activity.breadcrumbs',
async function(scope){

    const hooks = await scope.getService('hooks');
    const breadcrumbs = await scope.getService('breadcrumbs');

    function mount(){
        scope.on('breadcrumbs:resolve', async ({ url, response }) => {
            
            if (!url?.startsWith('portal/activity/timeline/')) return;

            const entry = response?.data?.entry;
            if (!entry){
                breadcrumbs.set([
                    { label: 'Timeline', href: 'portal/activity' },
                    { label: 'Post', current: true }
                ]);
                return;
            }
            // alert('person found');
            breadcrumbs.set([
                { label: 'entry', href: 'portal/activity' },
                { label: entry.id, current: true }
            ]);
        });
    }

    function unmount(){
        scope.off('breadcrumbs:resolve');
    }

    return { mount, unmount };
},{
     activateOn: (route) => (
        route === 'portal/activity' ||
        route.startsWith('portal/activity/')
    )
});