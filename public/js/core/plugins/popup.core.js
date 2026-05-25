__BORA_REGISTER_PLUGIN__('popup.core', async function(scope){

    // const $ = await scope.getService('jquery');
    const events = await scope.getService('events'); // optional
    const uiStack = await scope.getService('uiStack');

    let activePopup = null;

    function setActive(instance){
        activePopup = instance;
    }

    function getActive(){
        return activePopup;
    }

    /* ==================================================
       CLASS
    ================================================== */

    class BoraPopup {

        constructor(options = {}) {
            this._id = 'boraPopup_' + Math.random().toString(36).slice(2);

            this.options = Object.assign({
                containerId: 'bora_popup',
                onOpen: null,
                onLoaded: null,
                onClose: null
            }, options);
            this._initialTabLoaded = false;
            this._tabCache = {};
            this.init();
        }

        /* =========================
           INIT
        ========================= */

        init() {

            if ($('#' + this.options.containerId).length === 0) {

                $('body').append(`
                    <div class="popup" id="${this.options.containerId}">
                        <div class="popup-inner">
                            <div class="popup-container">
                                <div class="chat_hd">
                                    <div class="chat_tabs_container">
                                        <ul class="chat_hd_tbs"></ul>
                                    </div>
                                    <div class="chat_close">
                                        <div class="bck"></div>
                                    </div>
                                </div>
                                <div class="popup-append"></div>
                            </div>
                        </div>
                    </div>
                `);
            }

            this.$popup = $('#' + this.options.containerId);
            this.$append = this.$popup.find('.popup-append');
            this.$tabs   = this.$popup.find('.chat_hd_tbs');
            this.$close  = this.$popup.find('.chat_close .bck');

            this.bindCoreEvents();
        }

        bindCoreEvents() {
            this.$close.on(`click.${this._id}`, () => this.close());
            this.$popup.on(`click.${this._id}`, (e) => {
                if ($(e.target).is(this.$popup)) this.close();
            });
        }

        /* =========================
           LIFECYCLE
        ========================= */

        show() {
            this.$popup.fadeIn(200);
            $('body').css('overflow', 'hidden');

            uiStack?.register(this);

            if (this.options.onOpen) this.options.onOpen();

            scope && scope.emit && scope.emit('popup:open', this);
        }

        async close() {

            if (API.activePopup === this){
                API.activePopup = null;
            }

            // alert('close');

            const result =
                await scope.emit?.(
                    'popup:beforeClose',
                    this
                );

            /*
            | Any listener can cancel close
            */

            if(result === false){
                return;
            }
            
            this.$popup.fadeOut(200, () => {

                $('body').css('overflow', '');

                if (this.options.onClose) this.options.onClose();

                scope && scope.emit && scope.emit('popup:close', this);

                this.destroy();
            });

        }

        destroy() {

            uiStack?.unregister(this);

            this.$close.off(`.${this._id}`);
            this.$popup.off(`.${this._id}`);
            $(document).off(`.${this._id}`);

            this.$popup.remove();

            this.$popup = null;
            this.$append = null;
            this.$tabs = null;
            this.$close = null;

            this._tabCache = {};

            if (API.activePopup === this){
                API.activePopup = null;
            }
        }

        /* =========================
           OPEN / LOAD
        ========================= */

        open(urlOrHtml, callback) {

            this.show();

            if (typeof urlOrHtml === 'string' && !urlOrHtml.startsWith('<')) {
                this.load(urlOrHtml, callback);
            } else {
                this.setContent(urlOrHtml);
                if (callback) callback();
            }

            // alert('here');
        }

        load(url, callback) {

            this.$append.html('<div class="popup-loader">Loading...</div>');

            $.ajax({
                url,
                method: 'GET',
                dataType: 'html',
                success: (html) => {

                    this.setContent(html);

                    if (callback) callback();
                    if (this.options.onLoaded) this.options.onLoaded(url);

                    scope && scope.emit && scope.emit('popup:loaded', { url });
                },
                error: () => {
                    this.$append.html('<div class="popup-error">Failed to load content.</div>');
                }
            });
        }

        /* =========================
           CONTENT / TABS
        ========================= */
        setContent(content){

            const $html = $('<div>').html(content);
            const $foundTabs = $html.find('.chat_hd_tbs').first();

            // 🚨 ONLY extract server tabs if no controller tabs
            if (!$foundTabs.length || this.options.tabs){
                // skip replacing tabs
            } else {
                this.$tabs.html($foundTabs.html());
                $foundTabs.remove();
            }

            this.$append.html($html.html());

            // If controller tabs exist, re-bind them
            if (this.options.tabs){
                this._tabsInitialized = true;
                this.setTabs(this.options.tabs, this.options.activeTab);
            } else {
                this.bindTabs();
            }
        }

        bindTabs() {

            const $links = this.$tabs.find('a');

            if (!$links.length) return;

            $links.off('click').on('click', (e) => {

                e.preventDefault();

                const $link = $(e.currentTarget);

                $links.removeClass('active');
                $link.addClass('active');

                this.tryLoadTabContent($link);
            });

            if (!this.options.activeTab){
                $links.first().trigger('click');
            }
        }

        tryLoadTabContent($tab) {

            const url = $tab.data('url');
            const target = this.$append.find('#tabContentArea');

            if (!url) {

                const targetId = $tab.attr('href');

                if (targetId && this.$append.find(targetId).length) {
                    this.$append.find('.popup-append-section').hide();
                    this.$append.find(targetId).fadeIn(150);
                }

                return;
            }

            // if (this._tabCache[url]) {
            //     target.html(this._tabCache[url]);
            //     return;
            // }
            if (this._tabCache[url]) {

                target.html(this._tabCache[url]);

                if (this.options.onLoaded){
                    this.options.onLoaded(
                        url,
                        this._tabCache[url]
                    );
                }

                scope?.emit?.('popup:loaded', {
                    url,
                    html:this._tabCache[url],
                    popup:this
                });

                return;
            }

            target.html('<div class="popup-loader">Loading...</div>');

            $.ajax({
                url,
                method: 'GET',
                dataType: 'html',
                success: async (html) => {
                    this._tabCache[url] = html;
                    target.html(html);

                    if (this.options.onLoaded){
                        // this.options.onLoaded(url, html);
                        await this.options.onLoaded?.(url, html);
                    }

                    scope?.emit?.('popup:loaded', {
                        url,
                        html,
                        popup:this
                    });
                },
                error: () => {
                    target.html('<div class="popup-error">Failed to load content.</div>');
                }
            });
        }

        goToTab(tabId){

            // Guard against destroyed popup
            if (!this.$tabs || !this.$append){
                console.warn('[popup] Attempted to use destroyed popup');
                return;
            }
            
            const $tabLink = this.$tabs.find(`a[data-tab="${tabId}"], a[href="#${tabId}"]`);

            if (!$tabLink.length) return;

            this.$tabs.find('a').removeClass('active');
            $tabLink.addClass('active');

            this.tryLoadTabContent($tabLink);
        }

        // goToTabO(tabId) {

        //     const $tabLink = this.$tabs.find(`a[href="#${tabId}"]`);

        //     if (!$tabLink.length) return;

        //     this.$tabs.find('a').removeClass('active');
        //     $tabLink.addClass('active');

        //     this.tryLoadTabContent($tabLink);
        // }

        setTabs(tabs = [], activeTab = null){

            if (!tabs.length) return;

            const html = tabs.map(tab => {

                if (tab.url){
                    return `<li><a data-url="${tab.url}" data-tab="${tab.id}">${tab.label}</a></li>`;
                }

                return `<li><a href="#${tab.id}" data-tab="${tab.id}">${tab.label}</a></li>`;

            }).join('');

            this.$tabs.html(html);

            this.bindTabs();

            // Activate default tab
            if (activeTab){
                this.goToTab(activeTab);
            } else {
                if (!this._initialTabLoaded){
                    this._initialTabLoaded = true;
                    this.$tabs.find('a').first().trigger('click');
                }
            }
        }
    }

    /* ==================================================
       GLOBAL CLICK BRIDGE (SAFE)
    ================================================== */

    $(document).on('click', '.goto-tab', function(e){

        e.preventDefault();

        const tab = $(this).data('tab');
        const popup = API.getActive();

        if (popup && tab) popup.goToTab(tab);
    });

    /* ==================================================
       PUBLIC API
    ================================================== */

    const API = {

        create(options){
            const instance = new BoraPopup(options);

            // if (options.tabs){
            //     instance.setTabs(options.tabs, options.activeTab);
            // }
            // API.activePopup = instance;
            return instance;
        },

        getActive,
        setActive,
        activePopup: null
    };

    return API;
});