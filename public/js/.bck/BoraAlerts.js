// BoraAlerts.js
// Minimal alert, confirm, prompt and notify dialog plugin for BoraSlim
// Dominic Karau @ ILEBORA Technologies Ltd

var alertBora = addPlugin('alertBora', {
    pluginName: 'alertBora',
    modal: null,
    overlay: null,
    okButton: null,
    cancelButton: null,
    activeElement: null,
    defaults: {
        container: 'body',
        html: false,
        style: '',
        okText: 'OK',
        cancelText: 'Cancel',
        overlayTpl: '<div class="alertBora-overlay"></div>',
        modalTpl: `
            <form class="alertBora" enctype="multipart/form-data">
                <div class="alertBora-message"></div>
                <div class="alertBora-prompt"></div>
                <div class="alertBora-buttons"></div>
            </form>
        `,
        promptTpl: '<input class="alertBora-input" type="text" name="value">',
        show() {
            $(this.modal).add(this.overlay).fadeIn(150);
        },
        hide() {
            $(this.modal).add(this.overlay).fadeOut(150);
        }
    },
    init() {
        // Optionally preload templates or attach global listeners
        console.log('Alertbox plugin ready.');
    }
});

// Extend methods
alertBora.addMethods({
    show(type, message, options = {}) {
        const defer = $.Deferred();
        const settings = $.extend({}, this.defaults, options);
        let values = [];

        // Remove previous modals
        $(this.modal).add(this.overlay).remove();

        // Blur background focus
        this.activeElement = document.activeElement;
        if (this.activeElement) this.activeElement.blur();

        // Create DOM elements
        this.overlay = $(settings.overlayTpl).hide();
        this.modal = $(settings.modalTpl).hide();

        if (settings.style) this.modal.addClass(settings.style);

        // Message content
        const msgElem = this.modal.find('.alertBora-message');
        settings.html ? msgElem.html(message) : msgElem.text(message);

        // Prompt
        if (type === 'prompt') {
            this.modal.find('.alertBora-prompt').html(settings.promptTpl);
        } else {
            this.modal.find('.alertBora-prompt').empty();
        }

        // Buttons
        const buttons = this.modal.find('.alertBora-buttons');
        this.cancelButton = $('<button type="button" class="alertBora-cancel">')
            .text(settings.cancelText);
        this.okButton = $('<button type="submit" class="alertBora-ok">')
            .text(settings.okText);
        if (type !== 'alert') buttons.append(this.cancelButton);
        buttons.append(this.okButton);

        // Append to DOM
        $(settings.container).append(this.overlay).append(this.modal);
        settings.show.call({ modal: this.modal, overlay: this.overlay });

        // Optional centering
        if ($.fn.center) this.modal.center();

        // Form submit
        this.modal.on('submit.alertBora', (e) => {
            e.preventDefault();
            if (type === 'prompt') {
                const data = this.modal.serializeArray();
                data.forEach(item => {
                    values[item.name] = item.value;
                });
            } else {
                values = null;
            }
            this.hide(settings);
            defer.resolve(values);
        });

        // Cancel click
        this.cancelButton.on('click.alertBora', () => {
            this.hide(settings);
            defer.reject();
        });

        // Escape key
        $(document).on('keydown.alertBora', (e) => {
            if (e.keyCode === 27) {
                e.preventDefault();
                this.hide(settings);
                defer.reject();
            }
        });

        // Keep focus inside modal
        $(document).on('focus.alertBora', '*', (e) => {
            if (!$(e.target).closest('.alertBora').length) {
                e.stopPropagation();
                $(this.modal).find(':input:first').focus();
            }
        });

        // Focus default element
        if (type === 'prompt') {
            this.modal.find('.alertBora-input:first').focus();
        } else {
            this.okButton.focus();
        }

        return defer.promise();
    },

    hide(options) {
        const settings = $.extend({}, this.defaults, options);
        settings.hide.call({ modal: this.modal, overlay: this.overlay });
        $(document).off('.alertBora');
        this.modal.off('.alertBora');
        if (this.cancelButton) this.cancelButton.off('.alertBora');
        if (this.activeElement) this.activeElement.focus();
    },

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

// Initialize plugin
alertBora.init();
