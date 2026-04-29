__BORA_REGISTER_PLUGIN__('ContentManager', async function(scope){

    const $         = await scope.getService('jquery');
    const reactive  = await scope.getPlugin('state.reactive');
    const store     = await scope.getPlugin('store');

    const { reactive: r, effect } = reactive;

    // const store = r({
    //     route: null,
    //     page: null,
    //     filter: '',
    //     pageNumber: 1
    // });

    let currentRequest = null;

    function abortPrevious(){
        if(currentRequest && currentRequest.readyState !== 4){
            currentRequest.abort();
        }
    }

    function hydrate(response){
        store.page = {
            url: response?.url,
            blocks: response?.blocks || {},
            meta: response?.meta || {}
        };
    }

    function fetchPage(url){

        abortPrevious();

        $('.main-content').fadeTo(150, 0.3);

        currentRequest = $.ajax({
            url: url + '?t=1',
            method: 'GET',
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            dataType: 'json',

            success(response){
                hydrate(response);
                $('.main-content').fadeTo(200, 1);
            },

            error(){
                $('.main-content').fadeTo(200, 1);
            }
        });
    }

    // ----------------------------------------
    // 🔁 AUTO FETCH (reactive)
    // ----------------------------------------
    effect(() => {
        if(!store.route) return;

        // dependency tracked automatically:
        const url = store.route;
        const filter = store.filter;
        const page = store.pageNumber;

        const finalUrl = url + `?filter=${filter}&page=${page}`;

        fetchPage(finalUrl);
    });

    // ----------------------------------------
    // 🎯 AUTO RENDER (reactive)
    // ----------------------------------------
    effect(() => {
        const page = store.page;
        if(!page) return;

        const blocks = page.blocks || {};

        if(blocks.content){
            $('.content-area').html(blocks.content);
        }

        if(blocks.sidebar_menu){
            $('.features-list').html(blocks.sidebar_menu);
        }

        if(blocks.submenus){
            $('.submenu-area .sub_menu')?.html(blocks.submenus);
        }

        const $root = $('#page_content');

        scope.emit('view:mounted', {
            root: $root,
            type: 'page',
            url: page.url
        });
    });

    // ----------------------------------------
    // 🧩 PUBLIC API
    // ----------------------------------------
    return {
        mount(){
            console.log('[ContentManager Reactive] mounted');
        },
        store
    };
});