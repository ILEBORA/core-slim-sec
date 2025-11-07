// BoraAlerts.js
// Combines your alertbox modal with alertify-style notifier
// Fiki @ ILEBORA Technologies

// Register plugin in your system
var BoraAlerts = addPlugin('BoraAlerts', {
    pluginName: 'BoraAlerts',
    // modal state
    modal: null,
    overlay: null,
    okButton: null,
    cancelButton: null,
    activeElement: null,
    // notifier container & instances
    notifierContainer: null,
    notifiers: [],
    // defaults (exposed)
    defaults: {
        // modal defaults
        container: 'body',
        html: false,
        style: '',
        okText: 'OK',
        cancelText: 'Cancel',
        overlayTpl: '<div class="bora-overlay"></div>',
        modalTpl:
            '<form class="bora-alert" enctype="multipart/form-data">' +
                '<div class="bora-message"></div>' +
                '<div class="bora-prompt"></div>' +
                '<div class="bora-buttons"></div>' +
            '</form>',
        promptTpl: '<input class="bora-input" type="text" name="value">',

        // notifier defaults
        notifierDelay: 3, // seconds
        notifierPosition: 'bottom-right', // top-right | top-left | bottom-right | bottom-left | top-center | bottom-center
        notifierAutoDismiss: true,
        notifierAnimate: 'fade', // fade | slide
        notifierContainerTpl: '<div class="bora-notifier bora-pos-bottom-right"></div>',

        // animation hooks (you can override)
        showModal: function () { $(this.modal).add(this.overlay).fadeIn(150); },
        hideModal: function () { $(this.modal).add(this.overlay).fadeOut(150); },
    },

    init() {
        // create notifier container lazily on first notify
        // plugin init hook
        // console.log('BoraAlerts ready');
    }
});

// Helper to merge and expose global set
BoraAlerts.addMethods({
    set(keyOrObj, val) {
        if (typeof keyOrObj === 'object') {
            Object.assign(this.defaults, keyOrObj);
        } else {
            this.defaults[keyOrObj] = val;
        }
        // If notifier position changed, update container if exists
        if (keyOrObj === 'notifierPosition' || (typeof keyOrObj === 'object' && keyOrObj.notifierPosition)) {
            this._ensureNotifierContainer(true);
        }
        return this;
    },

    // Internal: ensure notifier container exists and position class updated
    _ensureNotifierContainer(forceRecreate) {
        var d = this.defaults;
        // compute class from notifierPosition
        var posClass = 'bora-pos-' + (d.notifierPosition || 'bottom-right').replace(/\s+/g, '-');
        if (this.notifierContainer && !forceRecreate) return this.notifierContainer;
        if (this.notifierContainer) {
            this.notifierContainer.remove();
            this.notifierContainer = null;
        }
        var tpl = d.notifierContainerTpl || '<div class="bora-notifier"></div>';
        this.notifierContainer = $(tpl);
        // normalize classes
        this.notifierContainer
            .removeClass (function (i, c) {
                return (c.match (/(^|\s)bora-pos-\S+/g) || []).join(' ');
            })
            .addClass(posClass);
        $('body').append(this.notifierContainer);
        return this.notifierContainer;
    },

    // Notifier / toast
    notify(message, type = 'info', delay) {
        var self = this;
        var d = self.defaults;
        self._ensureNotifierContainer();

        delay = (typeof delay === 'undefined') ? d.notifierDelay : delay;

        var toast = $('<div class="bora-toast bora-' + type + '"></div>');
        toast.html(message);

        // append and animate
        this.notifierContainer.append(toast);

        if (d.notifierAnimate === 'slide') {
            toast.hide().slideDown(180);
        } else {
            toast.hide().fadeIn(180);
        }

        // click to dismiss
        toast.on('click', function () {
            self._dismissToast($(this));
        });

        // auto dismiss
        if (d.notifierAutoDismiss && delay > 0) {
            var t = setTimeout(function () {
                self._dismissToast(toast);
            }, delay * 1000);
            // store timer
            toast.data('timer', t);
        }

        // store
        this.notifiers.push(toast);

        return {
            dismiss: function () {
                self._dismissToast(toast);
            }
        };
    },

    _dismissToast($toast) {
        if (!$toast || !$toast.length) return;
        var timer = $toast.data('timer');
        if (timer) {
            clearTimeout(timer);
        }
        if (this.defaults.notifierAnimate === 'slide') {
            $toast.slideUp(150, function () { $toast.remove(); });
        } else {
            $toast.fadeOut(150, function () { $toast.remove(); });
        }
    },

    // Convenience shortcuts
    success(msg, delay) { return this.notify(msg, 'success', delay); },
    error(msg, delay) { return this.notify(msg, 'error', delay); },
    warning(msg, delay) { return this.notify(msg, 'warning', delay); },
    info(msg, delay) { return this.notify(msg, 'info', delay); },

    // ---- MODAL API (based on your alertbox implementation) ----
    show(type, message, options = {}) {
        var defer = $.Deferred();
        var settings = $.extend({}, this.defaults, options);
        var values = [];

        // Remove previous
        $(this.modal).add(this.overlay).remove();

        // Save active element
        this.activeElement = document.activeElement;
        if (this.activeElement) this.activeElement.blur();

        // Create DOM
        this.overlay = $(settings.overlayTpl).hide();
        this.modal = $(settings.modalTpl).hide();

        if (settings.style) this.modal.addClass(settings.style);

        // message
        var msgElem = this.modal.find('.bora-message');
        settings.html ? msgElem.html(message) : msgElem.text(message);

        // prompt area or custom form HTML
        if (type === 'prompt') {
            // allow passing promptTpl override via options.promptTpl or options.prompt (string/element)
            if (options.prompt !== undefined) {
                this.modal.find('.bora-prompt').html(options.prompt);
            } else {
                this.modal.find('.bora-prompt').html(settings.promptTpl);
            }
        } else {
            this.modal.find('.bora-prompt').empty();
        }

        // Buttons
        var buttons = this.modal.find('.bora-buttons');
        this.cancelButton = $('<button type="button" class="bora-cancel bora-btn-cancel">')
            .text(options.cancelText || settings.cancelText);
        this.okButton = $('<button type="submit" class="bora-ok bora-btn-ok">')
            .text(options.okText || settings.okText);
        if (type !== 'alert') buttons.append(this.cancelButton);
        buttons.append(this.okButton);

        // Append
        $(settings.container).append(this.overlay).append(this.modal);
        // Show
        settings.showModal.call({ modal: this.modal, overlay: this.overlay });

        // Optional centering if $.fn.center exists
        if ($.fn.center) this.modal.center();

        // submit handler (OK)
        this.modal.on('submit.BoraAlerts', (e) => {
            e.preventDefault();
            if (type === 'prompt') {
                var data = this.modal.serializeArray();
                data.forEach(function (item) {
                    values[item.name] = item.value;
                });
            } else {
                values = null;
            }
            this.hide(settings);
            defer.resolve(values);
        });

        // Cancel
        this.cancelButton.on('click.BoraAlerts', () => {
            this.hide(settings);
            defer.reject();
        });

        // Escape key
        $(document).on('keydown.BoraAlerts', (e) => {
            if (e.keyCode === 27) {
                e.preventDefault();
                this.hide(settings);
                defer.reject();
            }
        });

        // Keep focus inside modal
        $(document).on('focus.BoraAlerts', '*', (e) => {
            if (!$(e.target).closest('.bora-alert').length) {
                e.stopPropagation();
                $(this.modal).find(':input:first').focus();
            }
        });

        // default focus
        if (type === 'prompt') {
            this.modal.find('.bora-input:first').focus();
        } else {
            this.okButton.focus();
        }

        return defer.promise();
    },

    hide(options) {
        var settings = $.extend({}, this.defaults, options);
        settings.hideModal.call({ modal: this.modal, overlay: this.overlay });
        $(document).off('.BoraAlerts');
        if (this.modal) this.modal.off('.BoraAlerts');
        if (this.cancelButton) this.cancelButton.off('.BoraAlerts');
        if (this.activeElement) this.activeElement.focus();
    },

    // modal shortcuts
    alert(message, options) {
        return this.show('alert', message, options);
    },
    confirm(message, options) {
        return this.show('confirm', message, options);
    },
    prompt(message, options) {
        return this.show('prompt', message, options);
    }
});

// Expose user-friendly variable
// Use camelCase API name requested: alertBora
var alertBora = BoraAlerts;
// Optionally attach to window if needed (not necessary per your request)
// window.alertBora = alertBora;

// expose to global scope for immediate use in pages
// (keeps it accessible without adding to jQuery global)
if (typeof window !== 'undefined') {
    window.alertBora = alertBora;
}

// Initialize plugin (call plugin init)
BoraAlerts.init();
alert('here');