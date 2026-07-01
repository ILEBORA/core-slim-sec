__BORA_REGISTER_PLUGIN__('ui.dropdown.panel', async function(scope){

    const dismissable = await scope.getService('ui.dismissable');
    const anchor = await scope.getPlugin('ui.anchor.positioner');
    const uiActions = await scope.getService('ui.actions');

    let panel = null;
    let dismissInstance = null;
    let openedMenu = null;
    let activeTrigger = null;

    const state = {
        mounted: false
    };

    function mount(){
        if (state.mounted) return;
        state.mounted = true;

        $(document).on('click','[data-dropdown]', openPanel);

        $(document).off('click.dropdown-panel').on('click.dropdown-panel', function(e){

            if(!openedMenu) return;

            const isInsidePanel  = panel && panel.has(e.target).length;
            const isTriggerClick = $(e.target).closest('[data-dropdown]').length;

            if(isInsidePanel || isTriggerClick) return;

            closePanel();

        });
    }

    async function openPanel(e){

        e.preventDefault();
        e.stopPropagation();

        const trigger = $(this);

        // $('[data-dropdown].opened').removeClass('opened');

        const type    = trigger.data('dropdown');

        if(
            activeTrigger &&
            activeTrigger[0] === trigger[0]
        ){

            closePanel();

            return;

        }

        closePanel();

        activeTrigger = trigger;
        activeTrigger.addClass('opened');

        

        showLoading(trigger);

        // const data = await loadPanel(type);
        const payload = trigger.data();
        const data = await loadPanel(
            type,
            payload
        );

        renderPanel(trigger, data);

    }

    function showLoading(trigger){

        const context = getContext(trigger);
        console.log('[CONTEXT]',context);
        panel = $(`
            <div class="dropdown-panel loading">
                <img src="assets/images/icons/ajax.gif">
            </div>
        `).appendTo(context);

        requestAnimationFrame(() => {
            position(trigger, panel);
        });

        openedMenu = panel;

    }

    async function loadPanel(type, payload){

        return $.get('api/modules/ui/dropdown',{
            type,
            ...payload
        });

    }

    function renderPanel(trigger, data){

        if(panel){
            panel.remove();
            panel = null;
        }

        // closePanel();

        const context = getContext(trigger);

        panel = $(data.html).appendTo(context);

        requestAnimationFrame(() => {
            position(trigger, panel);
        });

        dismissInstance = dismissable?.create(()=>{
            closePanel();
        });

        openedMenu = panel;

    }

    function getContext(trigger){

        const selector = trigger.data('dropdown-context');

        if(!selector){
            return $('body');
        }

        const context = $(selector);

        return context.length
            ? context
            : $('body');

    }

    function closePanel(){

        $(window).off('scroll.dropdown resize.dropdown');

        if(openedMenu){
            openedMenu.remove();
            openedMenu = null;
        }
        
        if(panel){
            panel.remove();
            panel = null;
        }

        if(dismissInstance){
            dismissInstance = null;
        }

        if(activeTrigger){

            activeTrigger.removeClass('opened');

            activeTrigger = null;

        }
    }

    function position(trigger, panel){
        const contextSelector =
            trigger.data('dropdown-context');

        const context =
            contextSelector
                ? $(contextSelector)
                : $('body');
                
        let options = {
                            align: 'right',
                            offsetY: 4,
                            arrow: true,
                            context
                        };
        anchor.position(trigger, panel, options);

        bindAutoPosition(trigger, panel, options);
    }

    function bindAutoPosition(trigger, panel, options){

        $(window)
            .off('scroll.dropdown resize.dropdown')
            .on('scroll.dropdown resize.dropdown', () => {

                if(!panel || !panel.is(':visible')) return;

                anchor.position(trigger, panel, options);
            });
    }

    function isOpen(trigger){
        return activeTrigger &&
            activeTrigger[0] === trigger[0];

    }

    function getTrigger(){
        return activeTrigger;

    }

    function unmount(){
        if (!state.mounted) return; 
        state.mounted = false;  

    }

    return { 
        mount, 
        unmount, 
        open, 
        closePanel, 
        
        isOpen,
        getTrigger
    };

});