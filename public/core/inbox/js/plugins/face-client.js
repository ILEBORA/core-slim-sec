// __BORA_REGISTER_PLUGIN__(
// 'ClientFace',
// async function(scope){

//     const state = await scope.getService('state');
//     const inbox = await scope.getPlugin('Inbox');

//     let unsubRoute;

//     function mount(){

//         // mount base layouts etc if needed
//         scope.getPlugin('Layouts')?.mount?.();

//         unsubRoute = state.subscribe('route', (url)=>{

//             if(url.startsWith('/portal/inbox')){
//                 inbox?.mount?.();
//             }else{
//                 inbox?.unmount?.();
//             }

//         });

//         console.log('[ClientFace] mounted');
//     }

//     function unmount(){

//         unsubRoute?.();
//         inbox?.unmount?.();
//         scope.getPlugin('Layouts')?.unmount?.();

//         console.log('[ClientFace] unmounted');
//     }

//     return { mount, unmount };

// },
// {
//     requires:['Inbox','state','Layouts']
// });