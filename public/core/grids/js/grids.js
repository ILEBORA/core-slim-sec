/**
 * Core Grids Plugin
 * Location: assets/core/grids/js/grids.js k
 */

appUI.grids = addPlugin(
    BoraPlugin,
    {
        pluginName: 'grids',
        debug: false,

        init: function () {
            BoraPlugin.init.call(this);
            if (this.debug) console.log('[Grids] init');

            this.bindUIEvents();
            this.bindPagination();
            this.bindDragScroll();
            this.scanOverflow();
        },

        /* -----------------------------------------
         * UI EVENTS (buttons, actions)
         * ----------------------------------------- */
        bindUIEvents() {
            const self = this;

            $(document)
                .off('click.gridsActions')
                .on('click.gridsActions', '[data-grid-action]', function (e) {
                    e.preventDefault();

                    const action = $(this).data('grid-action');
                    const $grid = $(this).closest('.grid-wrapper');

                    if (self.debug) {
                        console.log('[Grids] action:', action);
                    }

                    switch (action) {
                        case 'refresh':
                            self.refreshGrid($grid);
                            break;
                    }
                });
        },

        refreshGrid($grid) {
            const unique = $grid.find('[data-unique]').data('unique') || '';
            const grid   = $grid.data('grid-type') || 'card';

            new CallBora(`api/modules/grids/loader/load/1/${unique}/${grid}`)
                .setMethod("POST")
                .setCallback(res => {
                    if (res.success) {
                        $grid.replaceWith(res.html);
                    }
                })
                .build();
        },

        /* -----------------------------------------
         * PAGINATION
         * ----------------------------------------- */
        bindPagination() {
            const self = this;

            $(document)
                .off('click.gridsPagination')
                .on('click.gridsPagination', '.grid-pagination .page-btn', function () {
                    const $gridWrapper = $(this).closest('.grid-wrapper');
                    const page   = $(this).data('page');
                    const unique = $gridWrapper.find('[data-unique]').data('unique') || '';
                    const grid   = $gridWrapper.data('grid-type') || 'card';

                    if (self.debug) {
                        console.log('[Grids] paginate', page);
                    }

                    new CallBora(`api/modules/grids/loader/load/${page}/${unique}/${grid}`)
                        .setMethod("POST")
                        .setCallback(res => {
                            if (res.success) {
                                $gridWrapper.replaceWith(res.html);
                            }
                        })
                        .setError(xhr => console.error(xhr))
                        .build();
                });
        },

        /* -----------------------------------------
         * DRAG SCROLL
         * ----------------------------------------- */
        bindDragScroll() {
            $.fn.attachDragger = function () {
                let attachment = false;
                let lastPosition;

                this.on("mousedown mouseup mousemove", function (e) {
                    if (e.type === "mousedown") {
                        attachment = true;
                        lastPosition = [e.clientX, e.clientY];
                    }

                    if (e.type === "mouseup") attachment = false;

                    if (e.type === "mousemove" && attachment) {
                        const position = [e.clientX, e.clientY];
                        const diff = [
                            position[0] - lastPosition[0],
                            position[1] - lastPosition[1]
                        ];

                        this.scrollLeft -= diff[0];
                        this.scrollTop  -= diff[1];

                        lastPosition = position;
                    }
                });

                $(window).on("mouseup", () => attachment = false);
                return this;
            };
        },

        /* -----------------------------------------
         * OVERFLOW SCAN
         * ----------------------------------------- */
        scanOverflow() {
            const self = this;

            $('.grid-wrapper').each(function () {
                const content = this.querySelector('.table-opt-margin');
                if (!content) return;

                if (self.isOverflown(content)) {
                    //
                    $(".grid-wrapper").attachDragger();
                    //
                    $(this).attachDragger();
                    this.style.borderColor = '#db652e';

                    if (self.debug) {
                        console.log('[Grids] overflow detected', this);
                    }
                }
            });
        },

        isOverflown(el) {
            return el.scrollHeight > el.clientHeight ||
                   el.scrollWidth  > el.clientWidth;
        }
    }
);

// Optional
appUI.grids.setDebug(true);
appUI.grids.init();
// alert('Grids core 4');