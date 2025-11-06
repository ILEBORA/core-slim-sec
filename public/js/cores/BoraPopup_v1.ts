class BoraPopup {
    constructor(options = {}) {
        this.options = Object.assign({
            containerId: 'bora_popup',
            onOpen: null,
            onLoaded: null,
            onClose: null
        }, options);

        this.init();
    }

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
                                <div class="chat_close"><div class="bck"></div></div>
                            </div>
                            <div class="popup-append"></div>
                        </div>
                    </div>
                </div>
            `);
        }

        this.$popup = $('#' + this.options.containerId);
        this.$append = this.$popup.find('.popup-append');
        this.$tabs = this.$popup.find('.chat_hd_tbs');
        this.$close = this.$popup.find('.chat_close .bck');

        this.$close.on('click', () => this.close());
        this.$popup.on('click', (e) => {
            if ($(e.target).is(this.$popup)) this.close();
        });

        $(document).on('keyup', (e) => {
            if (e.key === "Escape") this.close();
        });
    }

    open(urlOrHtml, callback) {
        this.show();

        if (typeof urlOrHtml === 'string' && !urlOrHtml.startsWith('<')) {
            this.load(urlOrHtml, callback);
        } else {
            this.setContent(urlOrHtml);
            if (callback) callback();
        }
    }

    show() {
        this.$popup.fadeIn(200);
        $('body').css('overflow', 'hidden');
    }

    close() {
        this.$popup.fadeOut(200, () => {
            this.$append.empty();
            this.$tabs.empty();
            $('body').css('overflow', '');
            if (this.options.onClose) this.options.onClose();
        });
    }

    load(url, callback) {
        this.$append.html('<div class="popup-loader">Loading...</div>');
        $.ajax({
            url: url,
            method: 'GET',
            dataType: 'html',
            success: (html) => {
                this.setContent(html);
                if (callback) callback();
                if (this.options.onLoaded) this.options.onLoaded(url);
            },
            error: () => {
                this.$append.html('<div class="popup-error">Failed to load content.</div>');
            }
        });
    }

    setContent(content) {
        const $html = $('<div>').html(content);
        const $foundTabs = $html.find('.chat_hd_tbs').first();

        // Inject tabs if present
        if ($foundTabs.length) {
            this.$tabs.html($foundTabs.html());
            $foundTabs.remove();
        }

        this.$append.html($html.html());
        this.bindTabs();
    }

    bindTabs() {
        const $links = this.$tabs.find('a');
        if ($links.length) {
            $links.off('click').on('click', (e) => {
                e.preventDefault();
                const $link = $(e.currentTarget);
                const target = $link.attr('href');
                $links.removeClass('active');
                $link.addClass('active');
 
                this.$append.find('.popup-append-section').hide();
                this.$append.find(target).fadeIn(150);
            });
            $links.first().trigger('click');
        }
    }
}
