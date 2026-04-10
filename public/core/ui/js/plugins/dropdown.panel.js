__BORA_REGISTER_PLUGIN__('ui.dropdown.panel', async function(scope){

    const dismissable = await scope.getService('ui.dismissable');
    const anchor = await scope.getPlugin('ui.anchor.positioner');
    const uiActions = await scope.getService('ui.actions');

    let panel = null;
    let dismissInstance = null;
    let openedMenu = null;

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
        const type    = trigger.data('dropdown');

        closePanel();

        showLoading(trigger);

        const data = await loadPanel(type);

        renderPanel(trigger, data);

    }

    function showLoading(trigger){

        panel = $(`
            <div class="dropdown-panel loading">
                <img src="assets/images/icons/ajax.gif">
            </div>
        `).appendTo('body');

        requestAnimationFrame(() => {
            position(trigger, panel);
        });

        openedMenu = panel;

    }

    async function loadPanel(type){

        return $.get('api/modules/ui/dropdown',{
            type:type
        });

    }

    function renderPanel(trigger, data){

        closePanel();

        panel = $(data.html).appendTo('body');

        requestAnimationFrame(() => {
            position(trigger, panel);
        });

        dismissInstance = dismissable?.create(()=>{
            closePanel();
        });

        openedMenu = panel;

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
    }

    function position(trigger, panel){
        let options = {
                            align: 'right',
                            offsetY: 4,
                            arrow: true
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

    function unmount(){
        if (!state.mounted) return; 
        state.mounted = false;  

    }

    return { mount, unmount, closePanel};

});