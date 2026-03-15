__BORA_REGISTER_PLUGIN__('BoraPopupV2', function(scope){

    const $ = scope.getService('jquery');
    const events = scope.getService('events'); // optional
    const uiStack = scope.getService('uiStack');

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

            events && events.emit && events.emit('popup:open', this);
        }

        close() {

            this.$popup.fadeOut(200, () => {

                $('body').css('overflow', '');

                if (this.options.onClose) this.options.onClose();

                events && events.emit && events.emit('popup:close', this);

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

                    events && events.emit && events.emit('popup:loaded', { url });
                },
                error: () => {
                    this.$append.html('<div class="popup-error">Failed to load content.</div>');
                }
            });
        }

        /* =========================
           CONTENT / TABS
        ========================= */

        setContent(content) {

            const $html = $('<div>').html(content);
            const $foundTabs = $html.find('.chat_hd_tbs').first();

            if ($foundTabs.length) {
                this.$tabs.html($foundTabs.html());
                $foundTabs.remove();
            }

            this.$append.html($html.html());
            this.bindTabs();
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

            $links.first().trigger('click');
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

            if (this._tabCache[url]) {
                target.html(this._tabCache[url]);
                return;
            }

            target.html('<div class="popup-loader">Loading...</div>');

            $.ajax({
                url,
                method: 'GET',
                dataType: 'html',
                success: (html) => {
                    this._tabCache[url] = html;
                    target.html(html);
                },
                error: () => {
                    target.html('<div class="popup-error">Failed to load content.</div>');
                }
            });
        }

        goToTab(tabId) {

            const $tabLink = this.$tabs.find(`a[href="#${tabId}"]`);

            if (!$tabLink.length) return;

            this.$tabs.find('a').removeClass('active');
            $tabLink.addClass('active');

            this.tryLoadTabContent($tabLink);
        }
    }

    /* ==================================================
       GLOBAL CLICK BRIDGE (SAFE)
    ================================================== */

    $(document).on('click', '.goto-tab', function(e){

        e.preventDefault();

        const tab = $(this).data('tab');
        const popup = scope.runtimeInstance?.activePopup;

        if (popup && tab) popup.goToTab(tab);
    });

    /* ==================================================
       PUBLIC API
    ================================================== */

    const API = {

        create(options){
            const instance = new BoraPopup(options);
            API.activePopup = instance;
            return instance;
        },

        activePopup: null
    };

    return API;
});