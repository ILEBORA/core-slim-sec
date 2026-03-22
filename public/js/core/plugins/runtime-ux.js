__BORA_REGISTER_PLUGIN__('RuntimeUX', async function(scope){

    // const $ = await scope.getService('jquery');
    const config = await scope.config || {};

    let audioUnlocked = false;
    const notifySound = new Audio('assets/sound/doink.mp3');

    function mount(){
        console.log('[RuntimeUX] mounted');
        setupAudioUnlock();
        initCuriosity();
        emitStartup();

        if(config.dev){
            console.log('RuntimeUX initialized.');
        }
    }

    /* =========================
       AUDIO UNLOCK
    ========================= */

    function setupAudioUnlock(){

        function unlock(){

            if(audioUnlocked) return;

            notifySound.play().catch(()=>{});
            notifySound.pause();
            notifySound.currentTime = 0;

            audioUnlocked = true;

            if(config.dev){
                console.log('Audio unlocked.');
            }
        }

        window.addEventListener("click", unlock, { once:true });
        window.addEventListener("keydown", unlock, { once:true });
        window.addEventListener("touchstart", unlock, { once:true });
    }

    /* =========================
       CURIOSITY INIT
    ========================= */

    function initCuriosity(){

        const hasSeen = localStorage.getItem('has_seen_curiosity') === 'true';
        const prefers = window.APP_PREFERS_CURIOSITY === true 
                     || window.APP_PREFERS_CURIOSITY === 'true';

        const show = prefers || hasSeen;

        if(show){
            $('#curiosity-container').fadeIn(300);

            if(typeof curiosity !== 'undefined'){
                curiosity.startEngine();
            }
        }
        else{
            $('#landing-container').fadeIn(300);
        }
    }

    /* =========================
       STARTUP EVENT
    ========================= */

    function emitStartup(){
        scope.emit('runtime:uxReady');
    }

    return {
        mount
    };
});