__BORA_REGISTER_PLUGIN__('Sidebar', function(scope){

    const $ = scope.getService('jquery');
    const dismiss = scope.getService('dismiss');
    const navigation = scope.getService('navigation');
    const context = __BORA_APP__.service('context');
    const dismissable = scope.getService('uiDismissable');
    let sidebarInstance = null;

    let sidebar, main, dropMenu, burger;
    let isOpen = false;

    function mount(){
        $(function(){
            sidebar = $('#side-bar');
            main = $('.main-wrapper');
            dropMenu = $('.menu-container');
            burger = $('#burger');

            bindEvents();
        });

        console.log('[Sidebar] mounted');
        
    }

    function unmount(){
        $(document).off('.sidebar');
        console.log('[Sidebar] unmounted');
    }

    function bindEvents(){
        // console.log('dropMenu::',dropMenu);
        if(dropMenu.length == 0){
            dropMenu = $('.menu-container');
            console.log('dropMenu::',dropMenu);
        }
        // Burger toggle
        $(document).on('click.sidebar', '#burger, ._sideclose', toggleSidebar);

        // Profile dropdown
        $(document).on('click.sidebar', '.mini-photo-wrapper', openUserMenu);
            
        //     function(e){
        //     e.stopPropagation();
        //     // alert('Here');
        //     dropMenu.toggleClass('is-active');
        // });

        // Outside click
        $(document).on('click.sidebar', function(e){

            const $target = $(e.target);

            if ($target.closest('.side-bar, #burger, ._sideclose').length) return;
            if ($target.closest('.mini-photo-wrapper, .menu-container').length) return;

            closeSidebar();
            dropMenu.removeClass('is-active');
        });

        // Navigation click
        $(document).on('click.sidebar', '.features-list [data-url]', function(e){
            e.preventDefault();
            handleClick(this);
        });

        document.addEventListener('click', (e)=>{

            const el = e.target.closest('[data-sidebar-link]');
            if(!el) return;

            e.preventDefault();
            handleClick(el);

        });

        // Runtime hook integration
        scope.on('page.beforeLoad', handleBeforeLoad);
        scope.on('page.afterLoad', handleAfterLoad);
        scope.on('page.loaded', handlePageLoaded);
        // alert(window.location);
        // Also handle initial load
        highlightMenu(window.location);
        

        document.addEventListener('change', function(e){

            if (!e.target.matches('#changemenu')) return;

            const face = e.target.value;

            __BORA_APP__.service('context').set(face);
            window.APP_CURRENT_ROLE = face;
            $('[data-refresh-menu]').data('role', face);

            // After menu reload, highlight current route again
            // const cleanRoute = __BORA_APP__.service('router').clean();
            highlightMenu();
            
        });

        document.addEventListener('click', function(e){

            const btn = e.target.closest('[data-refresh-menu]');
            if (!btn) return;

            e.preventDefault();

            const role = btn.dataset.role || window.APP_CURRENT_ROLE;

            __BORA_APP__.service('menu').refresh(role);
        });

        // React to changes
        __BORA_APP__.on('context.changed', applyFace);

        // Apply initial state
        applyFace(context.get());

        //
        // scope.on('esc', onEscKeyPress);
    }

    function applyFace(face){
        document.body.classList.remove(
            'face-Client',
            'face-Administrator',
            'face-default'
        );
        document.body.classList.add(`face-${face}`);

        document.querySelectorAll('[data-refresh-menu]')
        .forEach(el => {
            el.setAttribute('data-role', face);
        });

    }

    function toggleSidebar(){
        const isOpening = !sidebar.hasClass('sideActive');
        if(isOpening){
            sidebar.addClass('sideActive');
            main.addClass('sideActive');
            burger.addClass('is-active');

            sidebarInstance = dismissable.create(()=>{
                closeSidebar();
            });

        } else {

            sidebarInstance?.close();
        }

    }

    function openUserMenu(e){
        e.stopPropagation();

        if(dropMenu.hasClass('is-active')){
            dropMenu.data('dismissInstance')?.close();
            return;
        }

        dropMenu.addClass('is-active');

        const instance = dismissable.create(()=>{
            dropMenu.removeClass('is-active');
            dropMenu.removeData('dismissInstance');
        });

        dropMenu.data('dismissInstance', instance);
    }

    function toggleSidebarO(){
        console.log('Bugger');
        sidebar.toggleClass('sideActive');
        main.toggleClass('sideActive');
        isOpen = sidebar.hasClass('sideActive');
        burger.toggleClass('is-active', isOpen);


        console.log('[Sidebar] '+isOpen);

    }

    function closeSidebar(){
        sidebar.removeClass('sideActive');
        main.removeClass('sideActive');
        burger.removeClass('is-active');
        isOpen = false;
    }

    // function closeMenus(){
    //     dropMenu.removeClass('is-active');
    // }

    // function onEscKeyPress(){
    //     closeSidebar();
    //     closeMenus();
    // }

    function handleClick(el){

        const url = $(el).data('url') || $(el).attr('href');
        if (!url) return;

        $('.features-list .active').removeClass('active');
        $(el).addClass('active loading');

        navigation.navigate(url)
            .finally(() => {
                // $(el).removeClass('loading');
            });
    }

    function handleBeforeLoad(url){
        window.history.pushState({ url }, '', url);
    }

    function handleAfterLoad(url){
        $('.features-item').removeClass('loading');
    }

    function handlePageLoaded(url){

        const current = normalizeUrl(url || window.location.location);
        // alert(url);
        $('.features-item').each(function(){
            const linkUrl = $(this).data('url');
            if (linkUrl === current){
                $('.features-item').removeClass('active');
                $(this).addClass('active');
                return false;
            }
        });

        highlightMenu(url);

        closeSidebar();

        updateSidebar();
    }

    function normalizeUrl(fullUrl){
        const base = window.__APP_BASE_PATH__ || '';

        if (!fullUrl) return '/';

        fullUrl = String(fullUrl);

        if (base && fullUrl.startsWith(base)){
            fullUrl = fullUrl.slice(base.length);
        }

        // remove query
        fullUrl = fullUrl.split('?')[0];

        // if (!fullUrl.startsWith('/')){
        //     fullUrl = '/' + fullUrl;
        // }

        return fullUrl || '';
    }

    function updateSidebar(){
        $.getJSON('api/modules/ui/sidebar-badges', function (badges) {
            //reset all
            $('.page-items-badges').text('');
            Object.entries(badges).forEach(([target, count]) => {
                if (!count) return;

                const id = target.replace('sidebar.', '');
                $(`.page-item-badge_${id}`)
                    .text(count)
                    .show();
            });
        });
    }

    // function setActiveFromRoute(currentUrl){
    //     $(function(){
    //         highlightMenu(cleanRoute);
    //     });
    // }

    function highlightMenu(cleanRoute){
        $(function(){
            cleanRoute = normalizeUrl(cleanRoute || window.location.location);
            const items = [...document.querySelectorAll('.features-item')];

            let bestItem = null;
            let bestLength = -1;

            items.forEach(item => {

                const dataUrl = (item.dataset.url || '').replace(/^\/|\/$/g,'');

                if (!dataUrl) return;

                if (
                    cleanRoute === dataUrl ||
                    cleanRoute.startsWith(dataUrl + '/')
                ) {
                    if (dataUrl.length > bestLength) {
                        bestLength = dataUrl.length;
                        bestItem = item;
                    }
                }
            });

            items.forEach(i => i.classList.remove('active'));
            bestItem?.classList.add('active');
        });
    }

    return { mount, unmount, close };

}, {
    requires:['jquery','hooks','navigation'],
    activateOn: () => true
});