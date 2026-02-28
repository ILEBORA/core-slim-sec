//Initialize
var manager = new WebConversationManager();
var curiosity = addPlugin(
    BoraPlugin, 
    {
        pluginName: 'curiosity',
        iconPickerContent : {},
        init : function(){
            BoraPlugin.init.call(this); // Call the base init method
            console.log('curiosity initialization.');

            // Load on init
            MemoryStore.load();

            console.log('Profile:', MemoryStore.get('profile'));
            console.log('AppData:', MemoryStore.get());

            let currentLevel = MemoryStore.get("curiosity.level") || 0;

            console.log('Level:', currentLevel);

        },
        startEngine(){
            manager = new WebConversationManager();
            //Welcome the user back
            manager.getWelcomeMessage();
            this.initDelegatedEvents();

            // still useful to catch unload
            window.addEventListener("beforeunload", updateLastActive);

        },

        autoStart(state = true){
            console.log(state);
            localStorage.setItem('has_seen_curiosity', state ? 'true' : 'false');
        },

        initDelegatedEvents() {
            const $container = $('#input-container');

            // delegate clicks on send button
            $container.on('click', '#send-btn', () => {
                this.sendInput();
                updateLastActive();
            });

            // delegate Enter key on input
            $container.on('keydown', '#user-input', (e) => {
                if (e.key === "Enter") {
                    this.sendInput();
                    updateLastActive();
                }
            });

            // delegate yes/no buttons → auto submit
            $container.on('click', '#user-input.yes-no button', (e) => {
                const $btn = $(e.currentTarget);
                $btn.addClass('active').siblings().removeClass('active');
                this.sendInput(); // call the same central sendInput
                updateLastActive();
            });
        },

        sendInput(){
            let val = null;
            const $input = $('#user-input');

            if ($input.length === 0) return;

            // Case 1: yes/no buttons inside #user-input
            if ($input.hasClass('yes-no')) {
                // look for clicked/active button
                val = $input.find('button.active').data('value');
                if (!val) {
                    // fallback: just use last clicked
                    val = $input.find('button.clicked').data('value');
                }
            }
            // Case 2: toggle switch
            else if ($input.hasClass('toggle')) {
                val = $('#yes-no-toggle').is(':checked') ? 'yes' : 'no';
            }
            // Case 3: regular input/select/textarea
            else {
                val = $input.val();
            }

            if (val) {
                val = val.toString().trim();
                manager.handleUserInput(val);
            }
        },
        start(){
            //Call curiosity start trigger
             appHooks.call('curiosity.start');
        },
        close(){
            //Close curiosity trigger
            appHooks.call('curiosity.close');
        }
        
    }
);

//debug
curiosity.setDebug(true);
 
curiosity.init();

// On load
$(function() {
    
});

function updateLastActive() {
    localStorage.setItem("lastActive", Date.now());
}

appHooks.addHook('curiosity.start',async function(){
    //Start.curiosity
    $('#landing-container').fadeOut(300, function(){
        $('#curiosity-container').fadeIn(300);
        curiosity.startEngine();
        curiosity.autoStart(true);
    });
});

appHooks.addHook('curiosity.close',async function(){
    //Stop.curiosity
    $('#curiosity-container').fadeOut(300, function(){
        $('#landing-container').fadeIn(300);
        curiosity.stop();
        curiosity.autoStart(false);
    });
});

