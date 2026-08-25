__BORA_REGISTER_SERVICE__('activity.tabs', async function(scope){

    const tabCache = new Map();
    const inflight = new Map();

    let mounted = false;


    /* ========================================
     * LOAD / MOUNT
     * ====================================== */

    async function load() {

        if (mounted) {
            return;
        }

        mounted = true;

        bind();
        bindEvents();
    }


    /* ========================================
     * TAB EVENTS
     * ====================================== */

    function bind() {

        $(document).on(
            'click.activityTabs',
            '.activity-tabs button',
            function () {

                const tab =
                    $(this).data('tab');

                if (!tab) {
                    return;
                }

                scope.emit(
                    'activity.tab.changed',
                    {
                        tab
                    }
                );

            }
        );

    }


    function bindEvents() {

        scope.on(
            'activity.tab.changed',

            async ({tab}) => {

                if (!tab) {
                    return;
                }

                activate(tab);

                /*
                 * Profile/static tab does not need
                 * remote content.
                 */
                if (tab === 'profile') {
                    return;
                }

                try {

                    showLoading(tab);

                    const html =
                        await getTabContent(tab);

                    render(tab, html);

                } catch (error) {

                    console.error(
                        '[activity.tabs] Failed to load tab',
                        tab,
                        error
                    );

                    render(
                        tab,
                        `
                        <div class="error">
                            <strong>
                                Unable to load this section.
                            </strong>
                        </div>
                        `
                    );

                }

            }
        );

    }


    /* ========================================
     * TAB CONTENT
     * ====================================== */

    async function getTabContent(tab) {

        /*
         * Activity has no personId, so the cache
         * key only needs the tab.
         */
        const cacheKey = tab;

        if (tabCache.has(cacheKey)) {
            return tabCache.get(cacheKey);
        }


        const key = `tab:${cacheKey}`;

        if (inflight.has(key)) {
            return inflight.get(key);
        }


        const promise = $.get(
            `api/modules/activity/timeline/tabs/${tab}`
        )
        .then(response => {

            let parsed = null;

            /*
             * API may return JSON or HTML.
             */
            if (
                typeof response === 'object' &&
                response !== null
            ) {

                parsed = response;

            } else if (
                typeof response === 'string'
            ) {

                try {

                    parsed = JSON.parse(response);

                } catch (e) {

                    parsed = null;

                }

            }


            /*
             * JSON error response
             */
            if (
                parsed &&
                typeof parsed === 'object' &&
                parsed.success === false
            ) {

                const html = `
                    <div class="error unauthorized">
                        <strong>
                            ${parsed.message || 'Error'}
                        </strong>
                    </div>
                `;

                tabCache.set(
                    cacheKey,
                    html
                );

                inflight.delete(key);

                return html;
            }


            /*
             * Assume HTML response.
             */
            tabCache.set(
                cacheKey,
                response
            );

            inflight.delete(key);

            return response;

        })
        .catch(error => {

            inflight.delete(key);

            throw error;

        });


        inflight.set(
            key,
            promise
        );

        return promise;
    }


    /* ========================================
     * UI
     * ====================================== */

    function activate(tab) {

        $('.activity-tabs button')
            .each(function () {

                $(this).toggleClass(
                    'active',
                    $(this).data('tab') === tab
                );

            });


        $('.activity-tab-panel')
            .each(function () {

                $(this).toggleClass(
                    'active',
                    $(this).data('tab') === tab
                );

            });

    }


    function showLoading(tab) {

        const $panel =
            $(`.activity-tab-panel[data-tab="${tab}"]`);

        if (!$panel.length) {
            return;
        }

        $panel.html(`
            <div class="loading-state small">
                Loading...
            </div>
        `);

    }


    function render(tab, html) {

        const $panel =
            $(`.activity-tab-panel[data-tab="${tab}"]`);

        if (!$panel.length) {
            return;
        }

        $panel.html(html);

    }


    /* ========================================
     * CACHE CONTROL
     * ====================================== */

    function invalidate(tab = null) {

        if (tab) {
            tabCache.delete(tab);
            inflight.delete(`tab:${tab}`);
            return;
        }

        tabCache.clear();
        inflight.clear();
    }


    function getActive() {

        const $button =
            $('.activity-tabs button.active');

        return $button.length
            ? $button.data('tab')
            : null;

    }


    return {
        load,
        getTabContent,
        activate,
        showLoading,
        render,
        getActive,
        invalidate
    };

});