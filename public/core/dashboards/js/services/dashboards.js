__BORA_REGISTER_SERVICE__('dashboards', async function(scope){

    const capability = await scope.getService('capability');
    const uiActions = await scope.getService('ui.actions');

    /*
    |--------------------------------------------------------------------------
    | Internal API exposed to optional features
    |--------------------------------------------------------------------------
    */
    const state = {
        mounted: false
    };

    function mount() {
        if (state.mounted) return;

        state.mounted = true;
        alert('Dashboard Actions mounted');

        init();
        
    }

    function unmount() {
        if (!state.mounted) return; // ⚠️ FIXED (was wrong)

        state.mounted = false;

        
    }

    const api = {

        bindClick(selector, handler){
            document.addEventListener('click', function(e){
                const el = e.target.closest(selector);
                if(!el) return;
                handler(el);
            });
        },

        getWidgets(){
            return document.querySelectorAll('.widget_container');
        }

    };

    /*
    |--------------------------------------------------------------------------
    | Core Dashboard Behaviour (Preserved From Old Script)
    |--------------------------------------------------------------------------
    */

    function bindCoreControls(){
        
        // Toggle dashboard control panel
        uiActions.register('dashboard.toggle-controls', (el)=>{
            el.classList.toggle('opened');

            const container = el.closest('.dash-controls-container');
            if(!container) return;

            container.classList.toggle('expanded');

            const controls = container.querySelector('.dash-controls');
            if(controls) controls.classList.toggle('expanded');

            const icon = el.querySelector('i');
            if(icon){
                icon.classList.toggle                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                ('fa-cogs');
                icon.classList.toggle('fa-times');
            }
        });
     

        // Hover tools (no jQuery required)
        document.addEventListener('mouseover', function(e){

            const container = e.target.closest('.widget_container');
            if(!container) return;

            if(container.contains(e.relatedTarget)) return; // 🔥 important

            const tools = container.querySelector('.widget_tools');
            if(tools) tools.style.display = 'block';
        });

        document.addEventListener('mouseout', function(e){

            const container = e.target.closest('.widget_container');
            if(!container) return;

            if(container.contains(e.relatedTarget)) return; // 🔥 important

            const tools = container.querySelector('.widget_tools');
            if(tools) tools.style.display = 'none';
        });
    }

    /*
    |--------------------------------------------------------------------------
    | Draggable Initialization (Preserved)
    |--------------------------------------------------------------------------
    */

    function initDraggable(){

        if(typeof ILEBORA === 'undefined') return;

        ILEBORA.use('assets/js/draggable', function(){

            if(typeof draggable === 'undefined') return;

            const widgets = document.querySelectorAll('.widget_container');

            widgets.forEach(el => {
                $(el).draggable({
                    handle: '.handle',
                    revert: true,
                    placeholder: true
                });
            });

            $('.parent').droppable({
                accept: '.drop',
                drop: function(event, ui){
                    $(this).append($(ui.draggable));
                }
            });

        });
    }

    /*
    |--------------------------------------------------------------------------
    | Init
    |--------------------------------------------------------------------------
    */

    function init(){
        alert('Dash tools');
        console.log('[Dashboards] initializing');

        bindCoreControls();
        initDraggable();

        // Expose capability AFTER base is ready
        capability?.provide('dashboards.ready', api);
    }

    /*
    |--------------------------------------------------------------------------
    | Auto Init When DOM Ready
    |--------------------------------------------------------------------------
    */

    // if(document.readyState === 'loading'){
    //     document.addEventListener('DOMContentLoaded', init);
    //     alert('here');
    //     $(function(){
    //         init();
    //     });
    // } else {
    //     init();
    // }

    // alert('here');

    return {
        api,
        mount,
        unmount
    };

},
{
    // requires: ['ui.actions']
});