var boraPopup = addPlugin(
    BoraPlugin,
    {
        pluginName: 'boraPopup',
        baseObj: null,
        _queue: [],
        _active: false,

        init() {
            BoraPlugin.init.call(this);
            console.log('boraPopup initialized with queue system.');
        },

        setupLibrary(c) {
            $(document).ready(() => {
                this.baseObj = $(c || 'body');
                this.trigger('librarySetup', this.baseObj);
            });
        },

        // Push a task to queue
        _enqueue(taskFn) {
            return new Promise((resolve) => {
                this._queue.push({ taskFn, resolve });
                this._processQueue();
            });
        },

        // Process queue one by one
        async _processQueue() {
            if (this._active || this._queue.length === 0) return;
            this._active = true;
            const { taskFn, resolve } = this._queue.shift();
            const result = await taskFn(); // Wait for popup to resolve
            resolve(result);
            this._active = false;
            // Continue with next
            this._processQueue();
        },
    }
);

// === Extended modal methods ===
boraPopup.addMethods({

    _build(content, options = {}) {
        const defaults = {
            title: options.title || '',
            closable: options.closable !== false,
            width: options.width || '400px',
            className: options.className || '',
        };

        const overlay = $('<div class="bora-overlay"></div>');
        const modal = $(`
            <div class="bora-popup ${defaults.className}">
                ${defaults.title ? `<div class="popup-header"><h3>${defaults.title}</h3></div>` : ''}
                <div class="popup-body">${content}</div>
                ${defaults.closable ? '<span class="popup-close">&times;</span>' : ''}
            </div>
        `).css('width', defaults.width);

        $('body').append(overlay, modal);
        overlay.fadeIn(120);
        modal.fadeIn(120);

        overlay.on('click', () => {
            if (defaults.closable) this.hide(modal, overlay);
        });
        modal.on('click', '.popup-close', () => this.hide(modal, overlay));

        return { overlay, modal };
    },

    hide(modal, overlay) {
        modal.fadeOut(150, () => modal.remove());
        overlay.fadeOut(150, () => overlay.remove());
    },

    // ====== Alert (Queue enabled) ======
    alert(message, title = 'Alert', callback) {
        return this._enqueue(() => new Promise((resolve) => {
            const { modal, overlay } = this._build(`
                <div class="popup-message">${message}</div>
                <div class="popup-actions">
                    <button class="btn-ok">OK</button>
                </div>
            `, { title });

            modal.find('.btn-ok').on('click', () => {
                this.hide(modal, overlay);
                if (typeof callback === 'function') callback();
                resolve(true);
            });
        }));
    },

    // ====== Confirm (Queue enabled) ======
    confirm(message, title = 'Confirm', callback) {
        return this._enqueue(() => new Promise((resolve) => {
            const { modal, overlay } = this._build(`
                <div class="popup-message">${message}</div>
                <div class="popup-actions">
                    <button class="btn-yes">Yes</button>
                    <button class="btn-no">No</button>
                </div>
            `, { title });

            modal.find('.btn-yes').on('click', () => {
                this.hide(modal, overlay);
                if (typeof callback === 'function') callback(true);
                resolve(true);
            });

            modal.find('.btn-no').on('click', () => {
                this.hide(modal, overlay);
                if (typeof callback === 'function') callback(false);
                resolve(false);
            });
        }));
    },

    // ====== Prompt (Queue enabled) ======
    prompt(message, defaultValue = '', title = 'Input Required', callback) {
        return this._enqueue(() => new Promise((resolve) => {
            const { modal, overlay } = this._build(`
                <div class="popup-message">${message}</div>
                <div class="popup-input">
                    <input type="text" class="prompt-input" value="${defaultValue}">
                </div>
                <div class="popup-actions">
                    <button class="btn-ok">OK</button>
                    <button class="btn-cancel">Cancel</button>
                </div>
            `, { title });

            const input = modal.find('.prompt-input');
            input.focus();

            modal.find('.btn-ok').on('click', () => {
                const val = input.val();
                this.hide(modal, overlay);
                if (typeof callback === 'function') callback(val);
                resolve(val);
            });

            modal.find('.btn-cancel').on('click', () => {
                this.hide(modal, overlay);
                if (typeof callback === 'function') callback(null);
                resolve(null);
            });

            input.on('keypress', (e) => {
                if (e.key === 'Enter') modal.find('.btn-ok').trigger('click');
            });
        }));
    },
});

boraPopup.init();
