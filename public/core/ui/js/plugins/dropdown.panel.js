__BORA_REGISTER_PLUGIN__('ui.dropdown.panel', async function(scope){

    const dismissable = await scope.getService('uiDismissable');

    let panel = null;
    let dismissInstance = null;
    let openedMenu = null;

    function mount(){
        $(document).on('click','[data-dropdown]', openPanel);
        $(document).on('click.dropdown-panel', function(e){
            if(!openedMenu) return;
            if($(e.target).closest('.dropdown-panel, [data-dropdown]').length){
                return;
            }
            dismissInstance?.close();
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

        position(trigger, panel);

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

        position(trigger, panel);

        dismissInstance = dismissable.create(()=>{
            closePanel();
        });

        openedMenu = panel;

    }

    function closePanel(){
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

        const pos = trigger.offset();

        panel.css({
            position:'absolute',
            top: pos.top + trigger.outerHeight(),
            right: pos.right ?? 0
        });

    }

    return { mount,closePanel};

});