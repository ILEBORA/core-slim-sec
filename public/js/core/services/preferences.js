__BORA_REGISTER_SERVICE__('preferences', async function(scope){

    const jquery = await scope.getService('jquery');
    const config = scope.config || {};
    const callbora = await scope.getService('callbora');

    let languages = null;
    let languagesPromise = null;

    const state = {
        theme: 'light-mode',
        sound: 'on',
        language: 'en',
        speech: null,
        mode: null,
        avatar: null
    };

    let saving = false;
    let loading = false;

    

    /* =========================
       LOAD
    ========================= */

    async function load(){

        try {
            if(loading) return;

            loading = true;
            
            const response = await fetch('api/modules/ui/userprefs', {
                method: 'GET',
                headers: { 'Content-Type': 'application/json' }
            });

            if(!response.ok){
                console.warn('Preferences API returned', response.status);
                return;
            }

            
            const data = await response.json() || {};
            Object.assign(state, data);
            apply();

            bindDOM();

            scope.emit('preferences:loaded', state);

            loading =  false;

        } catch(error){
            console.error('Preferences load failed:', error);
        }

        return state;
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


        $('[data-pref-bind]').each(function(){

            const key = $(this).data('pref-bind');

            updateBoundElement($(this), key);

        });

        $('[data-pref-toggle^="sound"]').find('i')
            .toggleClass('fa-volume-up', state.sound === 'on')
            .toggleClass('fa-volume-mute', state.sound === 'off');

        $('[data-pref-toggle^="theme"]').find('i')
            .toggleClass('fa-sun', state.theme === 'light-mode')
            .toggleClass('fa-moon', state.theme === 'dark-mode');


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

    async function set(key, value){
        if(state[key] === value) return;

        // before hook
        let prevented = false;

        scope.emit('preferences:before-change', {
            key,
            value,
            preventDefault: () => prevented = true
        });

        if(prevented) return;

        //proceed with change
        state[key] = value;

        apply();

        queueSave();
    }

    function get(key){
        return state[key];
    }

    let saveTimer = null;

    function queueSave(){

        clearTimeout(saveTimer);

        saveTimer = setTimeout(save, 300);
    }

    //
    /* =========================
    DOM BINDING
    ========================= */

    function bindDOM(){

        // bind values
        $('[data-pref-bind]').each(function(){

            const key = $(this).data('pref-bind');

            updateBoundElement($(this), key);
        });

    }

    async function loadLanguages(){

        if(languages) return languages;

        // prevent duplicate concurrent requests
        if(languagesPromise) return languagesPromise;

        languagesPromise = callbora.get('api/modules/ui/languages')
            .then(res => {
                languages = res || {};
                return languages;
            })
            .finally(() => {
                languagesPromise = null;
            });

        return languagesPromise;
    }

    function renderLanguageList(){

        let html = '<div class="lang-list">';

        Object.entries(languages).forEach(([code, lang]) => {

            html += `
            <div class="lang-item" data-lang-select="${code}">
                <strong>${lang.native}</strong>
                <small>${lang.completion}% translated</small>
            </div>`;
        });

        html += '</div>';
        return html;
    }



    function updateBoundElement($el, key){

        const value = state[key];

        if($el.is('img')){
            $el.attr('src', value);
        }
        else if($el.is('input,select,textarea')){
            $el.val(value);
        }
        else{
           $el.text(value ?? '');
        }

    }

    /* =========================
    EVENT BINDINGS
    ========================= */

    function bindEvents(){

        // Toggle preference
        $(document).on('click','[data-pref-toggle]',function(){

            const data = $(this).data('pref-toggle');

            if(!data) return;

            const parts = data.toString().split(':');

            const key = parts[0];

            const values = parts[1]
                ? parts[1].split(',')
                : ['light-mode','dark-mode'];

            const current = state[key];

            const next = current === values[0]
                ? values[1]
                : values[0];

            set(key,next);

        });

        // Explicit set
        $(document).on('click','[data-pref-set]',function(){

            const data = $(this).data('pref-set');

            if(!data) return;

            const parts = data.toString().split(':');

            if(parts.length !== 2) return;

            const key = parts[0];
            const value = parts[1];

            set(key,value);

        });

        $(document).on('click','.dropdown-toggle',function(){
            $(this)
                .closest('.dropdown-tool')
                .toggleClass('open');

        });

        $(document).on('click',function(e){
            if(!$(e.target).closest('.dropdown-tool').length){
                $('.dropdown-tool').removeClass('open');
            }
        });

    }

    bindEvents();

    return {
        load,
        save,
        apply,
        set,
        get,
        state,
        loadLanguages,
        renderLanguageList
    };
});