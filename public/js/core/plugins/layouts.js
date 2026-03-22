__BORA_REGISTER_PLUGIN__(
    'Layouts',
    async function(scope){

        // const $ = await scope.getService('jquery');
        const state = await scope.getService('state');

        let menus = new Map();
        let mounted = false;

        /* =========================
           INTERNAL
        ========================= */

        function addMenu(selector){

            const $el = $(selector);

            if(!$el.length){
                console.warn('[Layouts] Menu not found:', selector);
                return;
            }

            menus.set(selector, $el);
        }

        function getMenu(selector){
            return menus.get(selector) || null;
        }

        function closeAll(){
            $('.burger, .menu, .overlay, .side-bar, .cart')
                .removeClass('is-active');
        }

        function toggle(selector, mode){

            const $el = getMenu(selector);
            if(!$el) return;

            if(mode === 'open') $el.addClass('is-active');
            else if(mode === 'close') $el.removeClass('is-active');
            else $el.toggleClass('is-active');
        }

        /* =========================
           BINDINGS
        ========================= */

        function bind(){

            if(mounted) return;
            mounted = true;

            $(document)
                .on('click.layouts', '.menu-link', closeAll)
                .on('click.layouts', '.overlay', closeAll)
                .on('click.layouts', '#cart-btn', ()=>{
                    toggle('#cart');
                    toggle('.overlay');
                })
                .on('click.layouts', '#switch', ()=>{
                    document.documentElement.classList.toggle('darkmode');
                    document.body.classList.toggle('darkmode');

                    state.set('theme',
                        document.body.classList.contains('darkmode')
                            ? 'dark'
                            : 'light'
                    );
                });

            $(window).on('resize.layouts', ()=>{
                if($(window).width() >= 992){
                    toggle('#menu', 'close');
                    toggle('.overlay', 'close');
                }
            });
        }

        function unbind(){
            $(document).off('.layouts');
            $(window).off('.layouts');
            mounted = false;
        }

        /* =========================
           PUBLIC
        ========================= */

        function mount(){

            // addMenu('#menu');
            // addMenu('#header');
            // addMenu('#cart');
            // addMenu('.overlay');

            // bind();
            console.log('[Layouts] mounted');
        }

        function unmount(){
            unbind();
            menus.clear();
        }

        return {
            mount,
            unmount,
            closeAll,
            toggle
        };
    },
    {
        requires:['jquery','state']
    }
);