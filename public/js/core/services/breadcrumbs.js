__BORA_REGISTER_SERVICE__(
'breadcrumbs',
async function(scope){

    const hooks = await scope.getService('hooks');

    let crumbs = [];
    
    function set(newCrumbs = []){
        // alert('crumbs set');
        crumbs = normalize(newCrumbs);
        // hooks?.call('breadcrumbs:changed', crumbs);
        scope.emit('breadcrumbs:changed', crumbs);
    }

    function add(crumb){
        crumbs.push(normalizeItem(crumb));
        // hooks?.call('breadcrumbs:changed', crumbs);
        scope.emit('breadcrumbs:changed', crumbs);
    }

    function clear(){
        // alert('Clear crumbs');
        crumbs = [];
        // hooks?.call('breadcrumbs:changed', crumbs);
        scope.emit('breadcrumbs:changed', crumbs);
    }

    function get(){
        return crumbs;
    }

    /* --------------------------
       Helpers
    -------------------------- */

    function normalize(list){
        return list.map(normalizeItem);
    }

    function normalizeItem(item){
        if (typeof item === 'string'){
            return { label: item };
        }
        return {
            label: item.label || '',
            href: item.href || null,
            current: !!item.current
        };
    }

    /* --------------------------
       Auto: reset on navigation
    -------------------------- */

    // scope.on('page.beforeLoad', ()=>{
    //     clear();
    // });
    scope.on('page.beforeLoad', ({initial})=>{
        if (!initial){
            clear();
        }
    });

    return {
        set,
        add,
        clear,
        get
    };
},
{
    // requires:['hooks']
});