__BORA_REGISTER_PLUGIN__('ui.anchor.positioner', async function(scope){

    function position(trigger, panel, options = {}){

        const settings = {

            align: 'right',      // left | center | right
            offsetX: 0,
            offsetY: 0,
            margin: 10,
            arrow: true,
            flip: true,
            context: $('body'),

            ...options

        };

        const container = settings.context;

        // ---------------------------------------
        // Convert trigger coordinates into
        // coordinates relative to the container.
        // ---------------------------------------

        const triggerOffset = trigger.offset();

        const containerOffset =
            container[0] === document.body
                ? { left: 0, top: 0 }
                : container.offset();

        const pos = {

            left:
                triggerOffset.left -
                containerOffset.left,

            top:
                triggerOffset.top -
                containerOffset.top

        };

        const triggerWidth  = trigger.outerWidth();
        const triggerHeight = trigger.outerHeight();

        const panelWidth  = panel.outerWidth();
        const panelHeight = panel.outerHeight();

        const boundaryWidth  =
            container.innerWidth();

        const boundaryHeight =
            container.innerHeight();

        // ---------------------------------------
        // Horizontal alignment
        // ---------------------------------------

        let left;

        switch(settings.align){

            case 'left':

                left = pos.left;
                break;

            case 'center':

                left =
                    pos.left +
                    (triggerWidth / 2) -
                    (panelWidth / 2);

                break;

            default:

                left =
                    pos.left +
                    triggerWidth -
                    panelWidth;

        }

        left += settings.offsetX;

        // ---------------------------------------
        // Vertical alignment
        // ---------------------------------------

        let top =
            pos.top +
            triggerHeight +
            settings.offsetY;

        let flipped = false;

        const spaceBelow =
            boundaryHeight -
            (top + panelHeight);

        if(
            settings.flip &&
            spaceBelow < 0
        ){

            top =
                pos.top -
                panelHeight -
                settings.offsetY;

            flipped = true;

        }

        // ---------------------------------------
        // Clamp horizontally
        // ---------------------------------------

        if(left < settings.margin){

            left = settings.margin;

        }

        if(
            left + panelWidth >
            boundaryWidth - settings.margin
        ){

            left =
                boundaryWidth -
                panelWidth -
                settings.margin;

        }

        // ---------------------------------------
        // Clamp vertically
        // ---------------------------------------

        if(top < settings.margin){

            top = settings.margin;

        }

        // ---------------------------------------
        // Apply
        // ---------------------------------------

        panel.css({

            position: 'absolute',

            left,

            top

        });

        // ---------------------------------------
        // Arrow
        // ---------------------------------------

        if(settings.arrow){

            let arrowLeft =
                pos.left +
                (triggerWidth / 2) -
                left;

            arrowLeft = Math.max(
                12,
                Math.min(
                    panelWidth - 12,
                    arrowLeft
                )
            );

            panel.css(
                '--arrow-left',
                arrowLeft + 'px'
            );

            panel.toggleClass(
                'flipped',
                flipped
            );

        }

        return {

            left,
            top,
            flipped

        };

    }

    return {

        position

    };

});