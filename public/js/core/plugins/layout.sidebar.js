__BORA_REGISTER_PLUGIN__('Sidebar', function(scope){

    const $ = scope.getService('jquery');
    const hooks = scope.getService('hooks');
    const navigation = scope.getService('navigation');

    let sidebar, main, dropMenu, burger;
    let isOpen = false;

    function mount(){

        sidebar = $('#side-bar');
        main = $('.main-wrapper');
        dropMenu = $('.menu-container');
        burger = $('#burger');

        bindEvents();

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
    }

    function toggleSidebar(){
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
        // $('.features-item').removeClass('loading');
    }

    function handlePageLoaded(url){

        const current = normalizeUrl(url || window.location.pathname);

        $('.features-item').each(function(){
            const linkUrl = normalizeUrl($(this).data('url'));
            if (linkUrl === current){
                $('.features-item').removeClass('active');
                $(this).addClass('active');
                return false;
            }
        });
    }

    function normalizeUrl(url){
        return url
            .replace(window.location.origin, '')
            .split('?')[0]
            .replace(/\/$/, '');
    }

    return { mount, unmount };

}, {
    requires:['jquery','hooks','navigation'],
    activateOn: () => true
});