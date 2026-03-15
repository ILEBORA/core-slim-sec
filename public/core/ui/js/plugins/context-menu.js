__BORA_REGISTER_PLUGIN__('ContextMenu', function(scope){

    const hooks = scope.getService('hooks');
    const callbora   = scope.getService('callbora');
    const dismissable = scope.getService('uiDismissable');

    let openedMenu = null;
    let dismissInstance = null;

    function mount(){
        //alert('here context menu');
        $(document).on('click', '[data-context-trigger]', openMenu);
        // $(document).on('click', closeMenu);
        $(document).on('click.contextmenu', function(e){
            if(!openedMenu) return;
            if($(e.target).closest('.context-menu, [data-context-trigger]').length){
                return;
            }
            dismissInstance?.close();
        });
        $(document).on('click', '.context-menu [data-action]', dispatch);

        $(document).on('click','.context-menu-item',function(e){

            e.stopPropagation();

            const action = $(this).data('action');

            scope.getService('hooks')?.call?.(
                'contextMenu.action',
                action,
                this
            );

            closeMenu();

        });

    }

    async function openMenu(e){

        e.stopPropagation();

        const el   = $(this);
        const type = el.data('context-type');
        const id   = el.data('context-id');

        showLoading(el);

        const menu = await loadMenu(type,id);

        renderMenu(el,menu);

    }

    async function loadMenu(type,id){

        return $.get('api/modules/ui/contextmenu',{
            type:type,
            id:id
        });

    }

    function showLoading(trigger){

        closeMenu();

        const html = `
            <div class="context-menu context-loading">
                <img src="assets/images/icons/ajax.gif" width="16" height="16">
            </div>
        `;

        const menu = $(html).appendTo('body');

        positionMenu(trigger, menu);

        openedMenu = menu;

    }

    function renderMenu(trigger,data){

        const html = buildMenuHTML(data);

        closeMenu();

        const menu = $(html).appendTo('body');

        // const pos = trigger.offset();

        // menu.css({
        //     top:pos.top + trigger.outerHeight()/1.7,
        //     right: '4px'
        // });

        openedMenu = menu;

        positionMenu(trigger, menu);

        dismissInstance = dismissable.create(()=>{
            closeMenu();
        });

    }

    function positionMenu(trigger, menu){

        const pos = trigger.offset();

        const triggerWidth  = trigger.outerWidth();
        const triggerHeight = trigger.outerHeight();

        const menuWidth  = menu.outerWidth();
        const menuHeight = menu.outerHeight();

        const viewportWidth  = $(window).width();
        const viewportHeight = $(window).height();

        let top  = pos.top + triggerHeight/1.7;
        let left = pos.left;

        /* -------------------------
        Horizontal positioning
        --------------------------*/

        const spaceRight = viewportWidth - (pos.left + triggerWidth);
        const spaceLeft  = pos.left;

        if(spaceRight >= menuWidth){

            // open right
            left = pos.left + triggerWidth;

        }else if(spaceLeft >= menuWidth){

            // open left
            left = pos.left - menuWidth;

        }else{

            // fallback clamp
            left = Math.max(10, viewportWidth - menuWidth - 10);

        }

        /* -------------------------
        Vertical positioning
        --------------------------*/

        const spaceBottom = viewportHeight - (pos.top + triggerHeight);

        if(spaceBottom < menuHeight){

            top = pos.top - menuHeight;

        }

        /* -------------------------
        Apply
        --------------------------*/

        menu.css({
            position:'absolute',
            top:top,
            left:left
        });

    }

    function buildMenuHTML(data){

        let html = `<div class="context-menu">`;

        if(!data || !data.sections){
            html += `<div class="context-menu-empty">No actions</div>`;
            html += `</div>`;
            return html;
        }

        data.sections.forEach((section,index)=>{

            html += `<div class="context-menu-section">`;

            if(section.title){
                html += `<div class="context-menu-title">${section.title}</div>`;
            }

            html += `<ul class="context-menu-list">`;

            section.items.forEach(item=>{

                const cls = item.class ? item.class : '';

                html += `
                <li class="context-menu-item ${cls}"
                    data-action="${item.action || ''}">
                    ${item.label}
                </li>`;

            });

            html += `</ul>`;
            html += `</div>`;

            if(index < data.sections.length-1){
                html += `<div class="context-menu-divider"></div>`;
            }

        });

        html += `</div>`;

        return html;
    }

    function dispatch(){

        const action = $(this).data('action');

        hooks?.run?.('contextMenuAction',action,this);

        closeMenu();

    }

    function closeMenu(){

        if(openedMenu){
            openedMenu.remove();
            openedMenu = null;
        }

        if(dismissInstance){
            dismissInstance = null;
        }

    }

    return { mount };

});