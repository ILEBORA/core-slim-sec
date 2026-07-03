__BORA_REGISTER_PLUGIN__('ui.tabs', function(scope) {

    const cache = new Map();
    const inflight = new Map();
    const mounted = new WeakSet();

    const defaults = {
        lazy: true,
        cache: true,
        activeClass: 'active'
    };

    function mount(root = document) {
        root.querySelectorAll('[data-tabs]')
            .forEach(container => {
                alert('clicked');
                if (mounted.has(container)) {
                    return;
                }

                mounted.add(container);

                initialize(container);
            });
    }

    function initialize(container) {

        const config = getConfig(container);

        container.addEventListener('click', onClick);

        const initialTab =
            container.dataset.tabsDefault ||
            container.querySelector('[data-tabs-trigger]')
                ?.dataset.tabsTrigger;

        if (initialTab) {
            activate(container, initialTab);
        }

        scope.emit('tabs.mounted', {
            container,
            config
        });
    }

    async function onClick(e) {

        const trigger = e.target.closest('[data-tabs-trigger]');

        if (!trigger) return;

        const container = trigger.closest('[data-tabs]');

        if (!container) return;

        e.preventDefault();

        const tab = trigger.dataset.tabsTrigger;

        await activate(container, tab);
    }

    async function activate(container, tab) {

        const config = getConfig(container);

        setActiveTrigger(container, tab, config);
        setActivePanel(container, tab, config);

        const panel = getPanel(container, tab);

        if (!panel) {
            console.warn(`[ui.tabs] Missing panel for tab "${tab}"`);
            return;
        }

        scope.emit('tabs.changed', {
            container,
            tab,
            panel
        });

        const isLazy =
            panel.dataset.tabsLazy !== undefined
                ? panel.dataset.tabsLazy === 'true'
                : config.lazy;

        if (!isLazy) {
            return;
        }

        const alreadyLoaded =
            panel.dataset.loaded === 'true';

        if (alreadyLoaded) {
            return;
        }

        await load(container, tab);
    }

    async function load(container, tab) {

        const panel = getPanel(container, tab);

        if (!panel) return;

        showLoading(panel);

        try {

            scope.emit('tabs.beforeLoad', {
                container,
                tab,
                panel
            });

            const html =
                await resolveContent(container, tab);

            panel.innerHTML = html;

            panel.dataset.loaded = 'true';

            scope.emit('tabs.loaded', {
                container,
                tab,
                panel,
                html
            });

        } catch (err) {

            console.error(err);

            panel.innerHTML = `
                <div class="tabs-error">
                    Failed to load content
                </div>
            `;

            scope.emit('tabs.error', {
                container,
                tab,
                panel,
                error: err
            });
        }
    }

    async function resolveContent(container, tab) {

        const provider =
            container.dataset.tabsProvider;

        if (provider) {

            const plugin =
                await scope.getPlugin(provider);

            if (!plugin?.resolve) {
                throw new Error(
                    `[ui.tabs] Provider "${provider}" missing resolve()`
                );
            }

            return plugin.resolve({
                container,
                tab
            });
        }

        return fetchEndpoint(container, tab);
    }

    async function fetchEndpoint(container, tab) {

        const endpoint =
            container.dataset.tabsEndpoint;

        if (!endpoint) {
            throw new Error(
                '[ui.tabs] Missing data-tabs-endpoint'
            );
        }

        const url = buildUrl(container, endpoint, tab);

        const config = getConfig(container);

        if (config.cache && cache.has(url)) {
            return cache.get(url);
        }

        if (inflight.has(url)) {
            return inflight.get(url);
        }

        const promise = callbora
            .get(url)
            .then(response => {

                const html =
                    normalizeResponse(response);

                if (config.cache) {
                    cache.set(url, html);
                }

                inflight.delete(url);

                return html;
            })
            .catch(err => {

                inflight.delete(url);

                throw err;
            });

        inflight.set(url, promise);

        return promise;
    }

    function normalizeResponse(response) {

        let parsed = null;

        if (
            typeof response === 'object' &&
            response !== null
        ) {
            parsed = response;
        }

        else if (typeof response === 'string') {

            try {
                parsed = JSON.parse(response);
            }

            catch (_) {}
        }

        if (
            parsed &&
            typeof parsed === 'object' &&
            parsed.success === false
        ) {
            return `
                <div class="tabs-error">
                    ${parsed.message || 'Failed to load'}
                </div>
            `;
        }

        return response;
    }

    function buildUrl(container, endpoint, tab) {

        return endpoint
            .replace('{tab}', tab)
            .replace(
                '{id}',
                container.dataset.tabsId || ''
            );
    }

    function setActiveTrigger(container, tab, config) {

        container.querySelectorAll('[data-tabs-trigger]')
            .forEach(trigger => {

                trigger.classList.toggle(
                    config.activeClass,
                    trigger.dataset.tabsTrigger === tab
                );
            });
    }

    function setActivePanel(container, tab, config) {

        container.querySelectorAll('[data-tabs-panel]')
            .forEach(panel => {

                panel.classList.toggle(
                    config.activeClass,
                    panel.dataset.tabsPanel === tab
                );
            });
    }

    function getPanel(container, tab) {

        return container.querySelector(
            `[data-tabs-panel="${tab}"]`
        );
    }

    function showLoading(panel) {

        panel.innerHTML = `
            <div class="loading-state small">
                Loading...
            </div>
        `;
    }

    function getConfig(container) {

        return {

            ...defaults,

            lazy:
                container.dataset.tabsLazy !== 'false',

            cache:
                container.dataset.tabsCache !== 'false',

            activeClass:
                container.dataset.tabsActiveClass ||
                defaults.activeClass
        };
    }

    function clearCache(url = null) {

        if (!url) {
            cache.clear();
            return;
        }

        cache.delete(url);
    }

    function destroy(container) {

        if (!container) return;

        mounted.delete(container);

        container.removeEventListener('click', onClick);
    }

    scope.on('page.afterLoad', ({ root }) => {
        mount(root || document);
    });

    return {

        mount,
        activate,
        destroy,
        clearCache,

        cache,
        inflight
    };
});