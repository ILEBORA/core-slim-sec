__BORA_REGISTER_SERVICE__('sound', function(scope){

    const sounds = new Map();
    let unlocked = false;
    let initialized = false;

    function unlockAudio(){
        if (unlocked) return;

        const unlock = () => {
            const audio = new Audio();
            audio.src = '';
            audio.play().catch(()=>{});
            unlocked = true;

            document.removeEventListener('click', unlock);
            document.removeEventListener('touchstart', unlock);
        };

        document.addEventListener('click', unlock);
        document.addEventListener('touchstart', unlock);
    }

    function init(){
        if (initialized) return;
        initialized = true;

        unlockAudio();
        
        console.log('[SoundService] initialized');
    }

    function register(name, src, options = {}){
        sounds.set(name, {
            src,
            volume: options.volume ?? 1,
            preload: options.preload ?? true
        });

        if (options.preload !== false) {
            const audio = new Audio(src);
            audio.preload = 'auto';
        }
    }

    function play(name){
        const config = sounds.get(name);

        if (!config) {
            console.warn(`[SoundService] sound not found: ${name}`);
            return;
        }

        if (!unlocked) return;

        const audio = new Audio(config.src);
        audio.volume = config.volume;

        audio.play().catch(err=>{
            console.warn('[SoundService] play failed', err);
        });
    }

    const api = {
        init,
        register,
        play,
        isUnlocked: () => unlocked
    };

    // 🔥 CRITICAL: register first
    // scope.registerService('sound', api);

    // 🔥 CRITICAL: self-init immediately
    init();

    return api;
});