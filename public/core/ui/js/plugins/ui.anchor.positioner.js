__BORA_REGISTER_PLUGIN__('ui.anchor.positioner', async function(scope){

    function position(trigger, panel, options = {}){

        const settings = {
            align: 'right',        // 'left' | 'right' | 'center'
            offsetY: 0,
            offsetX: 0,
            margin: 10,
            arrow: true,
            flip: true,
            ...options
        };

        const pos = trigger.offset();

        const triggerWidth  = trigger.outerWidth();
        const triggerHeight = trigger.outerHeight();

        const panelWidth  = panel.outerWidth();
        const panelHeight = panel.outerHeight();

        const viewportWidth  = $(window).width();
        const viewportHeight = $(window).height();

        /* -------------------------
           Horizontal alignment
        --------------------------*/

        let left;

        if(settings.align === 'left'){
            left = pos.left;
        }

        else if(settings.align === 'center'){
            left = pos.left + (triggerWidth / 2) - (panelWidth / 2);
        }

        else{
            // right align (default)
            left = pos.left + triggerWidth - panelWidth;
        }

        left += settings.offsetX;

        /* -------------------------
           Vertical positioning
        --------------------------*/

        let top = pos.top + triggerHeight + settings.offsetY;

        let isFlipped = false;

        const spaceBottom = viewportHeight - (pos.top + triggerHeight);

        if(settings.flip && spaceBottom < panelHeight){
            top = pos.top - panelHeight - settings.offsetY;
            isFlipped = true;
        }

        /* -------------------------
           Clamp to viewport
        --------------------------*/

        if(left < settings.margin){
            left = settings.margin;
        }

        if(left + panelWidth > viewportWidth - settings.margin){
            left = viewportWidth - panelWidth - settings.margin;
        }

        if(top < settings.margin){
            top = settings.margin;
        }

        /* -------------------------
           Apply position
        --------------------------*/

        panel.css({
            position: 'absolute',
            top: top,
            left: left
        });

        /* =========================
           Arrow handling
        ==========================*/

        if(settings.arrow){

            const triggerCenter = pos.left + (triggerWidth / 2);

            let arrowLeft = triggerCenter - left;

            // clamp arrow inside panel
            arrowLeft = Math.max(12, Math.min(panelWidth - 12, arrowLeft));

            panel.css('--arrow-left', arrowLeft + 'px');
            panel.toggleClass('flipped', isFlipped);

        }

        return {
            top,
            left,
            flipped: isFlipped
        };
    }

    return { position };

});