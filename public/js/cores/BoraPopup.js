// Base popup class
class BoraPopup {
    constructor(options = {}) {
        this._id = 'boraPopup_' + Math.random().toString(36).slice(2);
        this.options = Object.assign({
            containerId: 'bora_popup',
            onOpen: null,
            onLoaded: null,
            onClose: null
        }, options);

        this.init();
        console.count('BoraPopup constructed');
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

        this.$close.on(`click.${this._id}`, () => this.close());
                this.$popup.on(`click.${this._id}`, (e) => {
            if ($(e.target).is(this.$popup)) this.close();
        });

        $(document).on(`keyup.${this._id}`, (e) => {
            if (e.key === "Escape") this.close();
        });
    }

    destroy() {
        console.log('DESTROY::' + this._id);
        // Unbind namespaced events
        this.$close.off(`.${this._id}`);
        this.$popup.off(`.${this._id}`);
        $(document).off(`.${this._id}`);

        // Remove DOM entirely
        this.$popup.remove();

        // Kill references
        this.$popup = null;
        this.$append = null;
        this.$tabs = null;
        this.$close = null;

        if (mPGs.activePopup === this) {
            mPGs.activePopup = null;
        }
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
            $('body').css('overflow', '');
            if (this.options.onClose) this.options.onClose();
             this.destroy();
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


// Add dynamic AJAX, caching, and go-to-tab support
BoraPopup.prototype._tabCache = {};

BoraPopup.prototype.tryLoadTabContent = function($tab) {
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
};

BoraPopup.prototype.bindTabs = function() {
    const $links = this.$tabs.find('a');
    if ($links.length) {
        $links.off('click').on('click', (e) => {
            e.preventDefault();
            const $link = $(e.currentTarget);
            $links.removeClass('active');
            $link.addClass('active');
            this.tryLoadTabContent($link);
        });
        $links.first().trigger('click');
    }
};

BoraPopup.prototype.goToTab = function(tabId) {
    const $tabLink = this.$tabs.find(`a[href="#${tabId}"]`);
    if ($tabLink.length) {
        this.$tabs.find('a').removeClass('active');
        $tabLink.addClass('active');
        this.tryLoadTabContent($tabLink);
    }
};


const originalClose = BoraPopup.prototype.close;
BoraPopup.prototype.close = function() {
    this._tabCache = {};
    originalClose.call(this);
};


// ✅ Listen for in-content tab switches (buttons, links, etc.)
$(document).on('click', '.goto-tab', function(e) {
    e.preventDefault();
    const targetTab = $(this).data('tab');
    if (targetTab) popup.goToTab(targetTab);
});