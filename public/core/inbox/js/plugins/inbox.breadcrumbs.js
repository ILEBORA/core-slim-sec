__BORA_REGISTER_PLUGIN__(
'inbox.breadcrumbs',
async function(scope){

    const hooks = await scope.getService('hooks');
    const breadcrumbs = await scope.getService('breadcrumbs');

    function mount(){

        scope.on('breadcrumbs:resolve', async ({ url, response }) => {
            console.log('resolve',{ url, response });
            if (!url?.startsWith('portal/inbox/thread/')) return;
            
            const thread = response?.data?.thread;
            if (!thread){
                breadcrumbs.set([
                    { label: 'Inbox', href: 'portal/inbox' },
                    { label: 'Thread', current: true }
                ]);
                return;
            }
            // alert('person found');
            breadcrumbs.set([
                { label: 'Inbox', href: 'portal/inbox' },
                { label: thread.display_name, current: true }
            ]);
        });
    }

    function unmount(){
        scope.off('breadcrumbs:resolve');
    }

    return { mount, unmount };
},{
     activateOn: (route) => (
        route === 'portal/inbox' ||
        route.startsWith('portal/inbox/')
    )
});