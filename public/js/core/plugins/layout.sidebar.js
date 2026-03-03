__BORA_REGISTER_PLUGIN__('Sidebar', function(scope){

    const $ = scope.getService('jquery');
    const hooks = scope.getService('hooks');
    const navigation = scope.getService('navigation');
    const context = __BORA_APP__.service('context');

    let sidebar, main, dropMenu, burger;
    let isOpen = false;

    function mount(){

        sidebar = $('#side-bar');
        main = $('.main-wrapper');
        dropMenu = $('.menu-container');
        burger = $('#burger');

        $(function(){
            bindEvents();
        });

        console.log('[Sidebar] mounted');
    }

    function unmount(){
        $(document).off('.sidebar');
        console.log('[Sidebar] unmounted');
    }

    function bindEvents(){

        // Burger toggle
        $(document).on('click.sidebar', '#burger, ._sideclose', toggleSidebar);

        // Profile dropdown
        $(document).on('click.sidebar', '.mini-photo-wrapper', function(e){
            e.stopPropagation();
            dropMenu.toggleClass('is-active');
        });

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
        hooks.add('page.beforeLoad', handleBeforeLoad);
        hooks.add('page.afterLoad', handleAfterLoad);
        hooks.add('page.loaded', handlePageLoaded);
        // alert(window.location);
        // Also handle initial load
        setActiveFromRoute(window.location);

        document.addEventListener('change', function(e){

            if (!e.target.matches('#changemenu')) return;

            const face = e.target.value;

            __BORA_APP__.service('context').set(face);
            window.APP_CURRENT_ROLE = face;
            $('[data-refresh-menu]').data('role', face);
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
        console.log('Bugger');
        sidebar.toggleClass('sideActive');
        main.toggleClass('sideActive');
        isOpen = sidebar.hasClass('sideActive');
        burger.toggleClass('is-active', isOpen);
    }

    function closeSidebar(){
        sidebar.removeClass('sideActive');
        main.removeClass('sideActive');
        burger.removeClass('is-active');
        isOpen = false;
    }

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

        setActiveFromRoute(url);
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

    function setActiveFromRoute(currentUrl){
        
        const cleanRoute = normalizeUrl(currentUrl);
        // alert(cleanRoute);
        $(function(){
            document.querySelectorAll('.features-item').forEach(item => {

                const dataUrl = item.getAttribute('data-url') ??'';
                // alert(dataUrl+' :: '+ cleanRoute);
                if (!dataUrl) return;

                // Prefix match
                if (cleanRoute === dataUrl){
                    item.classList.add('active');
                } else {
                    item.classList.remove('active');
                }
            });
        });
    }

    return { mount, unmount };

}, {
    requires:['jquery','hooks','navigation'],
    activateOn: () => true
});