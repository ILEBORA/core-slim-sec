__BORA_REGISTER_PLUGIN__('ui.anchor.positioner', async function(scope){

    function position(trigger, panel, options = {}) {
        // Viewport positioning for dropdowns that opt in.
        if (settings.strategy === 'fixed') {
            const triggerEl = trigger[0];
            const rect = triggerEl.getBoundingClientRect();

            const triggerWidth = rect.width;
            const triggerHeight = rect.height;
            const panelWidth = panel.outerWidth();
            const panelHeight = panel.outerHeight();

            const viewportWidth = window.innerWidth;
            const viewportHeight = window.innerHeight;
            const margin = settings.margin;

            let left;

            if (settings.align === 'left') {
                left = rect.left;
            } else if (settings.align === 'center') {
                left = rect.left + (triggerWidth / 2) - (panelWidth / 2);
            } else {
                left = rect.right - panelWidth;
            }

            left += settings.offsetX;

            let top = rect.bottom + settings.offsetY;
            let isFlipped = false;

            const spaceBelow = viewportHeight - rect.bottom;
            const spaceAbove = rect.top;

            if (
                settings.flip &&
                spaceBelow < panelHeight + margin &&
                spaceAbove > spaceBelow
            ) {
                top = rect.top - panelHeight - settings.offsetY;
                isFlipped = true;
            }

            left = Math.max(
                margin,
                Math.min(left, viewportWidth - panelWidth - margin)
            );

            top = Math.max(
                margin,
                Math.min(top, viewportHeight - panelHeight - margin)
            );

            panel.css({
                position: 'fixed',
                top: `${top}px`,
                left: `${left}px`,
                right: 'auto'
            });

            if (settings.arrow) {
                const triggerCenter = rect.left + (triggerWidth / 2);
                const arrowLeft = Math.max(
                    12,
                    Math.min(panelWidth - 12, triggerCenter - left)
                );

                panel.css('--arrow-left', `${arrowLeft}px`);
                panel.toggleClass('flipped', isFlipped);
            }

            return { top, left, flipped: isFlipped };
        }

        const settings = {
            align: 'right',        // 'left' | 'right' | 'center'
            offsetY: 0,
            offsetX: 0,
            margin: 10,
            arrow: true,
            flip: true,
            relativeTo: null,      // Optional: container for absolute positioning
            ...options
        };

        const triggerWidth  = trigger.outerWidth();
        const triggerHeight = trigger.outerHeight();

        const panelWidth  = panel.outerWidth();
        const panelHeight = panel.outerHeight();

        const pos = trigger.offset();

        /*
         * Default mode:
         * Preserve existing document-based positioning for
         * all dropdowns that do not specify relativeTo.
         */
        if (!settings.relativeTo) {

            const viewportWidth  = $(window).width();
            const viewportHeight = $(window).height();

            let left;

            if (settings.align === 'left') {
                left = pos.left;
            } else if (settings.align === 'center') {
                left = pos.left + (triggerWidth / 2) - (panelWidth / 2);
            } else {
                left = pos.left + triggerWidth - panelWidth;
            }

            left += settings.offsetX;

            let top = pos.top + triggerHeight + settings.offsetY;
            let isFlipped = false;

            const spaceBottom = viewportHeight - (pos.top + triggerHeight);

            if (settings.flip && spaceBottom < panelHeight) {
                top = pos.top - panelHeight - settings.offsetY;
                isFlipped = true;
            }

            if (left < settings.margin) {
                left = settings.margin;
            }

            if (left + panelWidth > viewportWidth - settings.margin) {
                left = viewportWidth - panelWidth - settings.margin;
            }

            if (top < settings.margin) {
                top = settings.margin;
            }

            panel.css({
                position: 'absolute',
                top: top,
                left: left
            });

            if (settings.arrow) {
                const triggerCenter = pos.left + (triggerWidth / 2);

                let arrowLeft = triggerCenter - left;

                arrowLeft = Math.max(
                    12,
                    Math.min(panelWidth - 12, arrowLeft)
                );

                panel.css('--arrow-left', arrowLeft + 'px');
                panel.toggleClass('flipped', isFlipped);
            }

            return {
                top,
                left,
                flipped: isFlipped
            };
        }

        /*
         * Container-relative mode:
         * Use only when the panel is appended to a positioned
         * container and should be positioned within it.
         */
        const container = $(settings.relativeTo);
        const containerEl = container[0];

        if (!containerEl) {
            return position(trigger, panel, {
                ...settings,
                relativeTo: null
            });
        }

        const containerOffset = container.offset();

        const scrollLeft = containerEl.scrollLeft;
        const scrollTop = containerEl.scrollTop;

        const containerWidth = containerEl.clientWidth;
        const containerHeight = containerEl.clientHeight;

        // Trigger coordinates relative to the container's padding edge.
        const triggerLeft = pos.left - containerOffset.left + scrollLeft;
        const triggerTop = pos.top - containerOffset.top + scrollTop;

        let left;

        if (settings.align === 'left') {
            left = triggerLeft;
        } else if (settings.align === 'center') {
            left = triggerLeft + (triggerWidth / 2) - (panelWidth / 2);
        } else {
            left = triggerLeft + triggerWidth - panelWidth;
        }

        left += settings.offsetX;

        let top = triggerTop + triggerHeight + settings.offsetY;
        let isFlipped = false;

        const spaceBottom = containerHeight - (triggerTop + triggerHeight);

        if (settings.flip && spaceBottom < panelHeight + settings.margin) {
            top = triggerTop - panelHeight - settings.offsetY;
            isFlipped = true;
        }

        // Clamp within the container.
        left = Math.max(
            settings.margin,
            Math.min(left, containerWidth - panelWidth - settings.margin)
        );

        top = Math.max(
            settings.margin,
            Math.min(top, containerHeight - panelHeight - settings.margin)
        );

        panel.css({
            position: 'absolute',
            top: top,
            left: left,
            right: 'auto'
        });

        if (settings.arrow) {
            const triggerCenter = triggerLeft + (triggerWidth / 2);

            let arrowLeft = triggerCenter - left;

            arrowLeft = Math.max(
                12,
                Math.min(panelWidth - 12, arrowLeft)
            );

            panel.css('--arrow-left', arrowLeft + 'px');
            panel.toggleClass('flipped', isFlipped);
        }

        return {
            top,
            left,
            flipped: isFlipped
        };
    }

    function positionO(trigger, panel, options = {}){

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