__BORA_REGISTER_PLUGIN__('Sidebar', async function(scope){

    // const $ = await scope.getService('jquery');
    // const dismiss = await scope.getService('dismiss');
    const navigation = await scope.getService('navigation');
    const context = await scope.getService('context');
    const dismissable = await scope.getService('ui.dismissable');
    const uiStack = await scope.getService('uiStack');
    
    let sidebarInstance = null;

    let sidebar, main, dropMenu, burger;
    let isOpen = false;

    let startX = 0;
    let currentX = 0;
    let startTime = 0;
    let dragging = false;

    const MAX_WIDTH = 280; // sidebar width (adjust to your CSS)

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
        // highlightMenu(window.location);
        

        document.addEventListener('change', async function(e){
            if (!e.target.matches('#changemenu')) return;

            const face = e.target.value;

            context.set(face);
            window.APP_CURRENT_ROLE = face;
            $('[data-refresh-menu]').data('role', face);

            const menu = await __BORA_APP__.service('menu'); // ✅ FIX
            await menu.refresh(face);

            // After menu reload, highlight current route again
            // const cleanRoute = await scope.service('router').clean();
            // alert(cleanRoute);
            highlightMenu();
            
        });

        document.addEventListener('click', async function(e){

            const btn = e.target.closest('[data-refresh-menu]');
            if (!btn) return;

            e.preventDefault();

            const role = btn.dataset.role || window.APP_CURRENT_ROLE;

            const menu = await __BORA_APP__.service('menu'); // ✅ FIX
            await menu.refresh(role);
        });

        // React to changes
        __BORA_APP__.on('context.changed', applyFace);

        // Apply initial state
        applyFace(context.get());

        //
        // scope.on('esc', onEscKeyPress);

        scope.on('sidebar.open', toggleSidebar);
        scope.on('sidebar.close', closeSidebar);

        //Swipe
        document.addEventListener('touchstart', (e) => {
            // Not top dismissable element
            if(uiStack && uiStack.size() > 0){
                return; // ❌ block swipe
            }

            const t = e.touches[0];

            // only allow swipe from left edge OR when open
            if(t.clientX > 40 && !sidebar.hasClass('sideActive')) return;

            startX = t.clientX;
            currentX = startX;
            startTime = Date.now();
            dragging = true;

            sidebar.css('transition', 'none');
            main.css('transition', 'none');

        }, { passive: true });

        document.addEventListener('touchmove', (e) => {

            if(!dragging) return;

            const t = e.touches[0];
            currentX = t.clientX;

            let delta = currentX - startX;

            // if sidebar already open, offset from full width
            if(sidebar.hasClass('sideActive')){
                delta = delta + MAX_WIDTH;
            }

            // clamp
            delta = Math.max(0, Math.min(MAX_WIDTH, delta));

            // apply transform
            sidebar.css('transform', `translateX(${delta - MAX_WIDTH}px)`);
            main.css('transform', `translateX(${delta}px)`);

        }, { passive: true });

        document.addEventListener('touchend', () => {

            if(!dragging) return;

            dragging = false;

            const delta = currentX - startX;
            const duration = Date.now() - startTime;

            const velocity = Math.abs(delta / duration); // px per ms

            const threshold = MAX_WIDTH * 0.4;

            const shouldOpen =
                delta > threshold || velocity > 0.5;

            const shouldClose =
                delta < -threshold || velocity > 0.5;

            sidebar.css('transition', '');
            main.css('transition', '');

            // reset transforms (we’ll rely on classes again)
            sidebar.css('transform', '');
            main.css('transform', '');

            if(!sidebar.hasClass('sideActive')){
                if(shouldOpen){
                    // toggleSidebar();
                    scope.emit('sidebar.open');
                }
            } else {
                if(shouldClose){
                    // closeSidebar();
                    scope.emit('sidebar.close');
                }
            }

        });

        scope.on('page.loaded', async (url) => {
            
        });
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
        $(el).find('.menu_loading').addClass('fa fa-spinner fa-spin');

        navigation.navigate(url)
            .finally(() => {
                // $(el).removeClass('loading');
            });
    }

    function handleBeforeLoad(url){
        // window.history.pushState({ url }, '', url);
        //  $('.features-item').removeClass('active');
        $(`[data-url="${url}"]`).addClass('loading');
    }

    function handleAfterLoad(url){
        $('.features-item').removeClass('loading');

        let el = $(`[data-url="${url}"`);
        if (!el) return;
        $(el).find('.menu_loading').removeClass('fa fa-spinner fa-spin');
    }

    function handlePageLoaded(ctx){

        // const current = normalizeUrl(url || window.location);
        const url = ctx?.url || window.location;
        const current = normalizeUrl(url);

        // alert(url);
        $('.features-item').each(function(){
            const linkUrl = $(this).data('url');
            if (linkUrl === current){
                $('.features-item').removeClass('active');
                $(this).addClass('active');
                return false;
            }
        });

        highlightMenu(current);

        closeSidebar();

        updateSidebar();
    }

    function normalizeUrl(fullUrl){
        const base = window.__APP_BASE_PATH__ || '';
        // alert(base);
        // alert(window.location);
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

    function highlightMenuO(cleanRoute){

        cleanRoute = normalizeUrl(cleanRoute || window.location);

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

        updateSidebar();
    }

    function highlightMenu(cleanRoute){
        
        $(function(){
            cleanRoute = normalizeUrl(cleanRoute || window.location);
            // alert(cleanRoute);
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

            //After load check 
            updateSidebar();
        });
    }

    return { mount, unmount, close };

}, {
    requires:['jquery','hooks','navigation'],
    // activateOn: () => true
});