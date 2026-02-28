__BORA_REGISTER_SERVICE__('preferences', function(scope){

    const $ = scope.getService('jquery');
    const config = scope.config || {};

    const state = {
        theme: 'light-mode',
        sound: null,
        speech: null,
        mode: null,
        avatar: null
    };

    let saving = false;

    /* =========================
       LOAD
    ========================= */

    async function load(){

        try {

            const response = await fetch('api/modules/ui/userprefs', {
                method: 'GET',
                headers: { 'Content-Type': 'application/json' }
            });

            if(response.ok){
                const data = await response.json();
                Object.assign(state, data);
                apply();
                scope.emit('preferences:loaded', state);
            }

        } catch(error){
            console.error('Preferences load failed:', error);
        }
    }

    /* =========================
       APPLY
    ========================= */

    function apply(){

        // Theme
        document.body.classList.toggle(
            'dark-mode',
            state.theme !== 'light-mode'
        );

        // Update theme button icon
        const $btn = $('.theme-btn #themeButton');

        if($btn.length){
            const icon = state.theme === 'light-mode'
                ? "<abbr class='fa fa-moon'></abbr>"
                : "<abbr class='fa fa-sun'></abbr>";

            $btn.html(icon);
        }

        scope.emit('preferences:applied', state);
    }

    /* =========================
       SAVE
    ========================= */

    async function save(){

        if(saving) return;

        saving = true;

        try {

            const res = await fetch('api/modules/ui/userprefs/save', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(state)
            });

            if(config.dev){
                console.log('Preferences saved.');
            }

            scope.emit('preferences:saved', state);

        } catch(error){
            console.error('Preferences save failed:', error);
        }

        saving = false;
    }

    /* =========================
       PUBLIC API
    ========================= */

    function set(key, value){
        state[key] = value;
        apply();
        return save();
    }

    function get(key){
        return state[key];
    }

    return {
        load,
        save,
        apply,
        set,
        get,
        state
    };
});