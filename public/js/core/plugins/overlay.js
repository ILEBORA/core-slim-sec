__BORA_REGISTER_PLUGIN__('Overlay', function(scope){

    const hooks = scope.getService('hooks');

    let $overlay;
    let $message;
    let $progress;

    let activeCount = 0;
    let slowTimer   = null;

    function init(){
        $overlay  = $('.mn-overlay');
        $message  = $overlay.find('.message');
        $progress = $overlay.find('.progress-bar');
    }

    function ensure(){
        if (!$overlay || !$overlay.length) init();
    }

    function show(msg = 'Loading...', options = {}){

        ensure();

        activeCount++;

        $message.html(msg);

        if (options.progress !== undefined){
            setProgress(options.progress);
        }

        $overlay.addClass('visible animated fadeIn');
        $('body').addClass('overlay-visible');
    }

    function hide(force = false){

        if (!force && activeCount > 1){
            activeCount--;
            return;
        }

        activeCount = 0;

        if (!$overlay) return;

        $overlay.removeClass('visible animated fadeIn');
        $('body').removeClass('overlay-visible');
        $message.html('');
        resetProgress();
    }

    function setProgress(percent){
        ensure();
        if (!$progress.length) return;

        $progress.css('width', percent + '%');
        $progress.text(percent + '%');
    }

    function resetProgress(){
        if ($progress && $progress.length){
            $progress.css('width', '0%').text('');
        }
    }

    /* ==================================================
       AUTO SLOW DETECTION
    ================================================== */

    function trackSlowRequest(){

        clearTimeout(slowTimer);

        slowTimer = setTimeout(()=>{
            show('Still working...', { progress: 30 });
        }, 400); // 400ms threshold
    }

    function clearSlow(){
        clearTimeout(slowTimer);
    }

    function wrap(promise, message = 'Processing...'){
        show(message);

        return promise.finally(()=>{
            hide(true);
        });
    }

    /* ==================================================
       HOOK BINDING
    ================================================== */

    function bindHooks(){

        hooks.add('page.beforeLoad', ()=>{
            trackSlowRequest();
        });

        hooks.add('page.afterLoad', ()=>{
            clearSlow();
            hide(true);
        });

        hooks.add('page.loadError', ()=>{
            clearSlow();
            hide(true);
        });

        hooks.add('jobqueue.start', ()=>{
            show('Processing job...');
        });

        hooks.add('jobqueue.complete', ()=>{
            hide(true);
        });
    }

    return {
        mount(){
            init();
            bindHooks();
        },

        show,
        hide,
        wrap,
        setProgress
    };
});