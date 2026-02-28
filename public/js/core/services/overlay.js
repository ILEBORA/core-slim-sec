__BORA_REGISTER_PLUGIN__('Overlay', function(scope){

    const hooks = scope.getService('hooks');

    let $overlay;
    let $message;

    function init(){
        $overlay = $('.mn-overlay');
        $message = $overlay.find('.message');
    }

    function show(msg = 'Loading...'){
        if(!$overlay || !$overlay.length) init();

        $message.html(msg);
        $overlay.addClass('visible animated fadeIn');
        $('body').addClass('overlay-visible');
    }

    function hide(){
        if(!$overlay) return;

        $overlay.removeClass('visible animated fadeIn');
        $('body').removeClass('overlay-visible');
        $message.html('');
    }

    function bindHooks(){

        hooks.add('page.beforeLoad', (url)=>{
            show('Loading...');
        });

        hooks.add('page.afterLoad', ()=>{
            hide();
        });

        hooks.add('page.loadError', ()=>{
            hide();
        });

        hooks.add('page.loadComplete', ()=>{
            hide();
        });
    }

    return {
        mount(){
            init();
            bindHooks();
        }
    };
});